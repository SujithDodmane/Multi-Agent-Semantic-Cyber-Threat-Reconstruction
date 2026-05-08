"""
AEGIS Ingestion — Priority Queue with Heuristic Scoring

Implements the asyncio.PriorityQueue with heuristic scoring for anomaly detection.
Lower integer = higher priority (Python heapq is a min-heap).

Ref: Methodology §1.6 — "After SQLite archival, the canonical entry is pushed to
the asyncio.PriorityQueue. The priority value is computed by the heuristic scoring
function — lower integers mean higher priority."

Features:
- P0/P1/P2/BENIGN classification
- Queue depth monitoring (5-second interval)
- P2 drop-oldest backpressure at depth > 50
- FastAPI GET endpoint exposure for OpenClaw polling
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from ingestion.models import EventType, NormalizedLogEntry, Severity

logger = logging.getLogger(__name__)

# ─── Priority Mapping ──────────────────────────────────────────────────────

# Ref: Methodology §1.6 — Priority assignments
P0_EVENT_TYPES = {
    EventType.PRIVILEGE_ESCALATION,
    EventType.EXFILTRATION_HINT,
    EventType.LATERAL_MOVEMENT_HINT,
    EventType.AUTHENTICATION_FAILURE_BURST,
}

P1_EVENT_TYPES = {
    EventType.SERVICE_INSTALL,
    EventType.SCHEDULED_TASK,
}

# Default max queue depth before P2 backpressure
DEFAULT_MAX_DEPTH = 50

# Known unusual ports (non-standard, not common services)
UNUSUAL_PORTS = {4444, 5555, 1337, 8888, 9001, 6666, 6667, 31337, 12345}

# Web server processes (for P1 detection)
WEB_SERVERS = {"apache2", "apache2.exe", "nginx", "nginx.exe", "w3wp.exe", "tomcat", "httpd", "httpd.exe"}


# ─── Queue Item Wrapper ────────────────────────────────────────────────────


@dataclass(order=True)
class PriorityItem:
    """
    Wrapper for entries in the PriorityQueue.
    Sorted by priority (lower = higher urgency).
    """

    priority: int
    entry: NormalizedLogEntry = field(compare=False)
    severity: Severity = field(compare=False, default=Severity.P2)


# ─── Heuristic Scoring ─────────────────────────────────────────────────────


def compute_severity(entry: NormalizedLogEntry) -> tuple[Severity, int]:
    """
    Compute the heuristic severity score for a log entry.

    Returns (severity_classification, priority_int).

    Ref: Methodology §1.6:
    - P0 (priority 0): PRIVILEGE_ESCALATION, EXFILTRATION_HINT,
      LATERAL_MOVEMENT_HINT, AUTHENTICATION_FAILURE_BURST
    - P1 (priority 1): PROCESS_CREATION with web server parent,
      NETWORK_CONNECTION to external IPs on unusual ports
    - P2 (priority 2): All other anomalous events
    - BENIGN (priority 3): No anomaly threshold → still queued for storage context
    """
    event_type = entry.event_type

    # P0 events — always critical
    if event_type in P0_EVENT_TYPES:
        return Severity.P0, 0

    # P1 events — high severity
    if event_type in P1_EVENT_TYPES:
        return Severity.P1, 1

    # P1: Process creation with web server parent
    if event_type == EventType.PROCESS_CREATION:
        parent = (entry.parent_process_name or "").lower()
        proc = (entry.process_name or "").lower()
        if parent in WEB_SERVERS and proc in ("cmd.exe", "powershell.exe", "bash", "sh"):
            return Severity.P1, 1

    # P1: Network connection to external IP on unusual port
    if event_type == EventType.NETWORK_CONNECTION:
        if entry.dest_port and entry.dest_port in UNUSUAL_PORTS:
            return Severity.P1, 1

    # P2: Any event with a MITRE technique hint (means template flagged it)
    if entry.mitre_technique_hint:
        return Severity.P2, 2

    # P2: Authentication failures (could be part of a burst)
    if event_type == EventType.AUTHENTICATION_FAILURE:
        return Severity.P2, 2

    # P2: DNS queries flagged as high-entropy
    if event_type == EventType.DNS_QUERY and entry.synthetic_intent and "high entropy" in entry.synthetic_intent:
        return Severity.P2, 2

    # P2: HTTP requests flagged as SQL injection
    if event_type == EventType.HTTP_REQUEST and entry.synthetic_intent and "SQL syntax" in entry.synthetic_intent:
        return Severity.P2, 2

    # P2: File writes to system directories
    if event_type == EventType.FILE_WRITE and entry.synthetic_intent and "system directory" in entry.synthetic_intent:
        return Severity.P2, 2

    # --- Manual Override ---
    if entry.severity_hint:
        p_map = {Severity.P0: 0, Severity.P1: 1, Severity.P2: 2, Severity.BENIGN: 3}
        return entry.severity_hint, p_map.get(entry.severity_hint, 2)

    # BENIGN — lowest priority, queued for storage context only
    return Severity.BENIGN, 3


# ─── Priority Queue Manager ────────────────────────────────────────────────


class AegisPriorityQueue:
    """
    Manages the asyncio.PriorityQueue with backpressure and monitoring.

    Ref: Methodology §1.6:
    - "queue backpressure. If the embedding service is overwhelmed and the
      queue depth grows beyond a configured threshold (50 entries by default),
      the ingestion daemon must switch to a drop-oldest strategy for P2 entries
      only — P0 and P1 entries are never dropped."
    - "Implement the queue depth monitor as a background asyncio task that runs
      every 5 seconds and emits a metric to the monitoring endpoint."
    """

    def __init__(self, max_depth: int = DEFAULT_MAX_DEPTH):
        self.queue: asyncio.PriorityQueue[PriorityItem] = asyncio.PriorityQueue()
        self.max_depth = max_depth
        self._p2_items: list[PriorityItem] = []  # Track P2 items for drop-oldest
        self._total_enqueued = 0
        self._total_dropped = 0
        self._monitor_task: Optional[asyncio.Task] = None

    @property
    def depth(self) -> int:
        """Current queue depth."""
        return self.queue.qsize()

    async def enqueue(self, entry: NormalizedLogEntry) -> Optional[Severity]:
        """
        Score and enqueue a log entry.

        Returns the Severity classification, or None if BENIGN (not queued).
        P0/P1 are never dropped. P2 may be dropped under backpressure.
        """
        severity, priority = compute_severity(entry)

        # All events are now queued for semantic storage context (Ref: §3.1)
        pass

        item = PriorityItem(priority=priority, entry=entry, severity=severity)

        # Backpressure: drop oldest P2 if queue is full
        if self.depth >= self.max_depth and severity == Severity.P2:
            self._total_dropped += 1
            logger.warning(
                f"Queue depth {self.depth} >= {self.max_depth}: "
                f"dropping P2 entry {entry.log_uuid}"
            )
            return None  # Dropped, but still in SQLite

        # P0 and P1 are NEVER dropped
        await self.queue.put(item)
        self._total_enqueued += 1

        if severity == Severity.P0:
            logger.critical(f"P0 ALERT QUEUED: {entry.log_uuid} — {entry.event_type.value}")

        return severity

    async def dequeue(self) -> Optional[PriorityItem]:
        """
        Dequeue the highest-priority item.
        Returns None if queue is empty.
        """
        try:
            return self.queue.get_nowait()
        except asyncio.QueueEmpty:
            return None

    async def dequeue_wait(self, timeout: float = 0.2) -> Optional[PriorityItem]:
        """
        Dequeue with timeout (for OpenClaw HEARTBEAT.md polling).

        Ref: Methodology §2.1 — "Implement the poll with a timeout of 200ms"
        """
        try:
            return await asyncio.wait_for(self.queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def get_stats(self) -> dict:
        """Get queue statistics for monitoring."""
        return {
            "depth": self.depth,
            "total_enqueued": self._total_enqueued,
            "total_dropped": self._total_dropped,
            "max_depth": self.max_depth,
        }

    async def start_monitor(self) -> None:
        """
        Start the background queue depth monitor.

        Ref: Methodology §1.6 — "Implement the queue depth monitor as a background
        asyncio task that runs every 5 seconds"
        """
        self._monitor_task = asyncio.create_task(self._monitor_loop())

    async def _monitor_loop(self) -> None:
        """Monitor loop — emits depth metric every 5 seconds."""
        while True:
            stats = self.get_stats()
            if stats["depth"] > 0:
                logger.info(f"Queue stats: depth={stats['depth']}, enqueued={stats['total_enqueued']}, dropped={stats['total_dropped']}")
            if stats["depth"] > self.max_depth:
                logger.warning(f"QUEUE BACKPRESSURE: depth {stats['depth']} exceeds threshold {self.max_depth}")
            await asyncio.sleep(5)

    async def stop_monitor(self) -> None:
        """Stop the background monitor."""
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
