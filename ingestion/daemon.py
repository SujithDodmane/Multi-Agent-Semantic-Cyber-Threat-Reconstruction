"""
AEGIS Ingestion — Watchdog File-Tailing Daemon

The main entry point for Plane 1. Monitors configured directories for log file
changes, processes new entries through the normalization pipeline, and feeds
the priority queue.

Ref: Methodology §1.1 — "The Python watchdog library monitors configured
directories for file modification events."

Key implementation details:
- Per-file position cursor persisted to disk (JSON)
- Inode-aware log rotation handling
- Async buffer for batch processing under high load
- Malformed entry routing to error queue

Ref: Methodology §1.1 — "The critical implementation detail is maintaining a
file position cursor per monitored file — the daemon must read only new bytes
since the last read, not re-process the entire file from the beginning."
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from watchdog.events import FileModifiedEvent, FileMovedEvent, FileDeletedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from ingestion.db import DatabaseManager
from ingestion.intent_translator import translate_entry
from ingestion.log_identifier import identify_log_type
from ingestion.models import NormalizedLogEntry, Severity
from ingestion.normalizer import normalize
from ingestion.priority_queue import AegisPriorityQueue

# Load environment
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("aegis.daemon")


# ─── Cursor Manager ────────────────────────────────────────────────────────


class CursorManager:
    """
    Manages per-file position cursors persisted to disk.

    Ref: Methodology §1.1 — "This cursor is persisted to disk (a simple JSON file
    per monitored path) so that a daemon restart does not cause duplicate log processing."

    Ref: Methodology TABLE 15 Pitfall — "Log file position cursor not persisted
    across daemon restarts"
    """

    def __init__(self, persist_dir: str):
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self._cursors: dict[str, int] = {}
        self._inodes: dict[str, int] = {}
        self._load_all()

    def _cursor_file(self, watched_path: str) -> Path:
        """Get the cursor file path for a watched file."""
        safe_name = watched_path.replace("/", "_").replace("\\", "_").replace(":", "_")
        return self.persist_dir / f"{safe_name}.cursor.json"

    def _load_all(self) -> None:
        """Load all persisted cursors."""
        for cursor_file in self.persist_dir.glob("*.cursor.json"):
            try:
                with open(cursor_file, "r") as f:
                    data = json.load(f)
                    path = data.get("path", "")
                    self._cursors[path] = data.get("position", 0)
                    self._inodes[path] = data.get("inode", 0)
            except (json.JSONDecodeError, IOError):
                continue

    def get_position(self, file_path: str) -> int:
        """Get the current cursor position for a file."""
        return self._cursors.get(file_path, 0)

    def set_position(self, file_path: str, position: int) -> None:
        """Update and persist the cursor position."""
        self._cursors[file_path] = position

        try:
            inode = os.stat(file_path).st_ino
        except OSError:
            inode = 0

        self._inodes[file_path] = inode
        self._persist(file_path)

    def _persist(self, file_path: str) -> None:
        """Write cursor state to disk."""
        cursor_file = self._cursor_file(file_path)
        data = {
            "path": file_path,
            "position": self._cursors.get(file_path, 0),
            "inode": self._inodes.get(file_path, 0),
        }
        try:
            with open(cursor_file, "w") as f:
                json.dump(data, f)
        except IOError as e:
            logger.error(f"Failed to persist cursor for {file_path}: {e}")

    def check_rotation(self, file_path: str) -> bool:
        """
        Check if a file has been rotated (new inode).

        Ref: Methodology §1.1 — "when a log file is truncated or replaced,
        the cursor must reset to position 0 for the new file inode."
        """
        try:
            current_inode = os.stat(file_path).st_ino
        except OSError:
            return False

        stored_inode = self._inodes.get(file_path, 0)
        if stored_inode != 0 and current_inode != stored_inode:
            logger.info(f"File rotation detected for {file_path} (inode {stored_inode} → {current_inode})")
            self._cursors[file_path] = 0
            self._inodes[file_path] = current_inode
            self._persist(file_path)
            return True
        return False

    def reset(self, file_path: str) -> None:
        """Reset cursor for a file (on rotation or deletion)."""
        self._cursors[file_path] = 0
        self._inodes.pop(file_path, None)
        self._persist(file_path)


# ─── Log Event Handler ─────────────────────────────────────────────────────


class LogEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler that processes new log entries.

    Ref: Methodology §1.1 — "The event handler must not process entries synchronously
    — it must read available lines, push them to an internal buffer, and return
    immediately so the watchdog thread is never blocked."
    """

    def __init__(
        self,
        cursor_manager: CursorManager,
        buffer: asyncio.Queue,
        loop: asyncio.AbstractEventLoop,
    ):
        super().__init__()
        self.cursor_manager = cursor_manager
        self.buffer = buffer
        self.loop = loop

    def on_created(self, event) -> None:
        """Handle file creation — treat exactly like modification."""
        self.on_modified(event)

    def on_modified(self, event: FileModifiedEvent) -> None:
        """Handle file modification — read new lines and buffer them."""
        if event.is_directory:
            return

        file_path = event.src_path

        # Check for rotation
        self.cursor_manager.check_rotation(file_path)

        try:
            position = self.cursor_manager.get_position(file_path)

            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                # Check if file was truncated (size < cursor)
                f.seek(0, 2)  # Seek to end
                file_size = f.tell()

                if file_size < position:
                    # File was truncated — reset cursor
                    logger.info(f"File truncated: {file_path}, resetting cursor")
                    position = 0

                f.seek(position)
                new_lines = f.readlines()
                new_position = f.tell()

            if new_lines:
                # Push lines to buffer asynchronously — don't block watchdog thread
                for line in new_lines:
                    line = line.strip()
                    if line:
                        # Thread-safe: use call_soon_threadsafe
                        self.loop.call_soon_threadsafe(
                            self.buffer.put_nowait,
                            (file_path, line),
                        )

                self.cursor_manager.set_position(file_path, new_position)

        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")

    def on_moved(self, event: FileMovedEvent) -> None:
        """
        Handle file move (rotation).
        Ref: Methodology §1.1 — "FileMovedEvent handlers must reset the cursor"
        """
        if not event.is_directory:
            self.cursor_manager.reset(event.src_path)
            logger.info(f"File moved: {event.src_path} → {event.dest_path}")

    def on_deleted(self, event: FileDeletedEvent) -> None:
        """
        Handle file deletion.
        Ref: Methodology §1.1 — "FileDeletedEvent handlers must reset the cursor"
        """
        if not event.is_directory:
            self.cursor_manager.reset(event.src_path)
            logger.info(f"File deleted: {event.src_path}")


# ─── Main Daemon ───────────────────────────────────────────────────────────


class AegisDaemon:
    """
    Main ingestion daemon orchestrating the full Plane 1 pipeline.

    Pipeline flow:
    1. Watchdog detects file change → lines buffered
    2. Buffer consumer identifies log type
    3. Normalizes to canonical schema
    4. Generates synthetic intent
    5. Stores in SQLite (with SHA-256 hash)
    6. Scores and enqueues to priority queue
    """

    def __init__(self):
        # Configuration from environment
        self.watch_dirs = os.getenv("LOG_WATCH_DIRS", "./logs").split(",")
        cursor_dir = os.getenv("CURSOR_PERSIST_DIR", "./data/cursors")
        db_path = os.getenv("SQLITE_DB_PATH", "./data/aegis.db")
        max_queue = int(os.getenv("QUEUE_MAX_DEPTH", "50"))

        # Components
        self.cursor_manager = CursorManager(cursor_dir)
        self.db = DatabaseManager(db_path)
        self.priority_queue = AegisPriorityQueue(max_depth=max_queue)
        self.buffer: asyncio.Queue = asyncio.Queue()
        self.observer: Optional[Observer] = None

        # Stats
        self._processed = 0
        self._errors = 0
        self._running = False

    async def start(self) -> None:
        """Start the daemon."""
        logger.info("=" * 60)
        logger.info("AEGIS Ingestion Daemon starting...")
        logger.info(f"Monitoring directories: {self.watch_dirs}")
        logger.info("=" * 60)

        self._running = True
        loop = asyncio.get_event_loop()

        # Set up watchdog observer
        self.observer = Observer()
        handler = LogEventHandler(self.cursor_manager, self.buffer, loop)

        for watch_dir in self.watch_dirs:
            watch_dir = watch_dir.strip()
            if os.path.isdir(watch_dir):
                self.observer.schedule(handler, watch_dir, recursive=True)
                logger.info(f"Watching: {watch_dir}")
            else:
                logger.warning(f"Directory not found: {watch_dir}")
                os.makedirs(watch_dir, exist_ok=True)
                self.observer.schedule(handler, watch_dir, recursive=True)
                logger.info(f"Created and watching: {watch_dir}")

        self.observer.start()

        # Initialize API with shared state
        from ingestion.api import app as api_app, init_api
        init_api(self.priority_queue, self.db)

        # Start uvicorn server
        import uvicorn
        config = uvicorn.Config(api_app, host="127.0.0.1", port=8000, log_level="info")
        self.server = uvicorn.Server(config)
        self.server_task = asyncio.create_task(self.server.serve())

        # Start queue monitor
        await self.priority_queue.start_monitor()

        # Main processing loop
        try:
            await self._process_loop()
        except asyncio.CancelledError:
            logger.info("Daemon shutting down...")
        finally:
            await self.stop()

    async def _process_loop(self) -> None:
        """
        Main processing loop — consumes buffered lines.

        Processes each line through the full pipeline:
        identify → normalize → translate → store → enqueue
        """
        while self._running:
            try:
                # Get next buffered line (with timeout to check _running flag)
                try:
                    file_path, raw_line = await asyncio.wait_for(
                        self.buffer.get(), timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue

                await self._process_line(file_path, raw_line)

            except Exception as e:
                self._errors += 1
                logger.error(f"Processing error: {e}", exc_info=True)

    async def _process_line(self, file_path: str, raw_line: str) -> None:
        """
        Process a single log line through the full pipeline.

        Ref: Abstract Report §2.3 — Data Flow: End-to-End
        """
        try:
            # 1. Identify log type
            log_source, parsed, format_type = identify_log_type(file_path, raw_line)

            if parsed is None:
                logger.debug(f"Empty/unparseable line from {file_path}")
                return

            # 2. Normalize to canonical schema
            entry = normalize(log_source, parsed, raw_line)

            # 3. Generate synthetic intent (THE MOST IMPORTANT STEP)
            entry = translate_entry(entry)

            # 4. Store in SQLite (with SHA-256 hash already computed)
            self.db.store_log_entry(entry)

            # 5. Score and enqueue
            severity = await self.priority_queue.enqueue(entry)

            self._processed += 1

            if severity and severity != Severity.BENIGN:
                logger.info(
                    f"[{severity.value}] {entry.event_type.value} | "
                    f"{entry.hostname} | {entry.synthetic_intent[:80]}..."
                )

        except Exception as e:
            self._errors += 1
            logger.error(f"Pipeline error for line from {file_path}: {e}")
            # Store in dead-letter queue
            try:
                self.db.store_dead_letter(
                    work_type="INGESTION",
                    payload={"file_path": file_path, "raw_line": raw_line[:500]},
                    failure_reason=str(e),
                )
            except Exception:
                pass  # Last resort — don't crash the daemon

    async def stop(self) -> None:
        """Stop the daemon gracefully."""
        self._running = False

        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)

        await self.priority_queue.stop_monitor()

        logger.info(f"Daemon stopped. Processed: {self._processed}, Errors: {self._errors}")
        logger.info(f"Queue stats: {self.priority_queue.get_stats()}")

    def get_stats(self) -> dict:
        """Get daemon statistics."""
        return {
            "processed": self._processed,
            "errors": self._errors,
            "queue": self.priority_queue.get_stats(),
            "running": self._running,
        }


# ─── Entry Point ────────────────────────────────────────────────────────────


def main():
    """Main entry point for `python -m ingestion.daemon`."""
    daemon = AegisDaemon()

    async def run():
        # Handle graceful shutdown
        loop = asyncio.get_event_loop()

        def shutdown_handler():
            logger.info("Shutdown signal received")
            asyncio.create_task(daemon.stop())

        try:
            loop.add_signal_handler(signal.SIGINT, shutdown_handler)
            loop.add_signal_handler(signal.SIGTERM, shutdown_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

        await daemon.start()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")


if __name__ == "__main__":
    main()
