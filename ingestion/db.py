"""
AEGIS Ingestion — SQLite Database Layer

SQLAlchemy + SQLite with WAL mode for concurrent read/write.

Ref: Methodology §1.5 — "The SQLite database uses Write-Ahead Logging (WAL) mode.
WAL allows concurrent readers to access the database while the ingestion daemon
is writing — this is critical because the Correlation SKILL.md (in Plane 3) may
need to read raw log entries from SQLite while new entries are being written."

Tables:
  - log_entries: All canonical schema fields with indexes
  - dead_letter_queue: Failed work items for retry
    Ref: Methodology §4.3
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from ingestion.models import NormalizedLogEntry

logger = logging.getLogger(__name__)

Base = declarative_base()


# ─── SQLite WAL Mode ────────────────────────────────────────────────────────


def _set_sqlite_wal_mode(dbapi_conn, connection_record):
    """
    Enable WAL mode on SQLite connection.
    Ref: Methodology §1.5 — "Without WAL mode, SQLite's default locking will
    cause the reader to block, introducing latency spikes"
    """
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")  # Good performance with WAL
    cursor.execute("PRAGMA busy_timeout=5000")  # 5s wait on lock
    cursor.close()


# ─── Log Entries Table ──────────────────────────────────────────────────────


class LogEntryRow(Base):
    """
    SQLite table for normalized log entries.

    Ref: Methodology §1.5 — "the primary table is log_entries with columns for
    all canonical schema fields. Create indexes on event_timestamp, source_ip,
    and process_name. Do not index sha256_hash."
    """

    __tablename__ = "log_entries"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Mandatory fields
    log_uuid = Column(String(36), unique=True, nullable=False, index=True)
    ingestion_timestamp = Column(String(50), nullable=False)
    event_timestamp = Column(String(50), nullable=False)
    event_type = Column(String(50), nullable=False)
    hostname = Column(String(255), nullable=False, default="unknown")
    sha256_hash = Column(String(64), nullable=False)  # No index per methodology
    raw_payload = Column(Text, nullable=False)
    synthetic_intent = Column(Text, nullable=False, default="")

    # Optional fields
    source_ip = Column(String(45))
    dest_ip = Column(String(45))
    source_port = Column(Integer)
    dest_port = Column(Integer)
    process_name = Column(String(255))
    parent_process_name = Column(String(255))
    user_account = Column(String(255))
    event_code = Column(String(20))
    file_path = Column(Text)
    registry_key = Column(Text)
    command_line_args = Column(Text)
    dns_query = Column(String(512))
    http_url = Column(Text)
    http_method = Column(String(10))
    bytes_sent = Column(Integer)
    bytes_received = Column(Integer)
    mitre_technique_hint = Column(String(20))

    # Indexes (per methodology §1.5)
    __table_args__ = (
        Index("idx_event_timestamp", "event_timestamp"),
        Index("idx_source_ip", "source_ip"),
        Index("idx_process_name", "process_name"),
    )


# ─── Dead Letter Queue Table ───────────────────────────────────────────────


class DeadLetterEntry(Base):
    """
    Dead-letter queue for failed work items.

    Ref: Methodology §4.3 — "The dead-letter queue is a SQLite table with columns
    for: dlq_uuid, work_type, payload, failure_reason, failed_at, retry_count, resolved"
    """

    __tablename__ = "dead_letter_queue"

    id = Column(Integer, primary_key=True, autoincrement=True)
    dlq_uuid = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    work_type = Column(String(30), nullable=False)  # EMBEDDING / CORRELATION / TIMELINE_SYNTHESIS
    payload = Column(Text, nullable=False)  # JSON blob
    failure_reason = Column(Text, nullable=False)
    failed_at = Column(String(50), nullable=False)
    retry_count = Column(Integer, nullable=False, default=0)
    resolved = Column(Boolean, nullable=False, default=False)


# ─── Database Manager ──────────────────────────────────────────────────────


class DatabaseManager:
    """Manages SQLite database connections and operations."""

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or os.getenv("SQLITE_DB_PATH", "./data/aegis.db")

        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)

        # Create engine with WAL mode
        self.engine = create_engine(
            f"sqlite:///{self.db_path}",
            echo=False,
            pool_pre_ping=True,
        )

        # Register WAL mode pragma
        event.listen(self.engine, "connect", _set_sqlite_wal_mode)

        # Create tables
        Base.metadata.create_all(self.engine)

        # Session factory
        self.SessionLocal = sessionmaker(bind=self.engine)

        logger.info(f"Database initialized at {self.db_path} with WAL mode")

    def get_session(self) -> Session:
        """Get a new database session."""
        return self.SessionLocal()

    def store_log_entry(self, entry: NormalizedLogEntry) -> None:
        """
        Store a normalized log entry in SQLite.

        Ref: Methodology §1.5 — "SHA-256 Hashing & SQLite Archival"
        """
        row = LogEntryRow(
            log_uuid=entry.log_uuid,
            ingestion_timestamp=entry.ingestion_timestamp,
            event_timestamp=entry.event_timestamp,
            event_type=entry.event_type.value,
            hostname=entry.hostname,
            sha256_hash=entry.sha256_hash,
            raw_payload=entry.raw_payload,
            synthetic_intent=entry.synthetic_intent,
            source_ip=entry.source_ip,
            dest_ip=entry.dest_ip,
            source_port=entry.source_port,
            dest_port=entry.dest_port,
            process_name=entry.process_name,
            parent_process_name=entry.parent_process_name,
            user_account=entry.user_account,
            event_code=entry.event_code,
            file_path=entry.file_path,
            registry_key=entry.registry_key,
            command_line_args=entry.command_line_args,
            dns_query=entry.dns_query,
            http_url=entry.http_url,
            http_method=entry.http_method,
            bytes_sent=entry.bytes_sent,
            bytes_received=entry.bytes_received,
            mitre_technique_hint=entry.mitre_technique_hint,
        )

        with self.get_session() as session:
            session.add(row)
            session.commit()

    def store_dead_letter(
        self,
        work_type: str,
        payload: dict,
        failure_reason: str,
    ) -> None:
        """
        Store a failed work item in the dead-letter queue.

        Ref: Methodology §4.3
        """
        entry = DeadLetterEntry(
            dlq_uuid=str(uuid.uuid4()),
            work_type=work_type,
            payload=json.dumps(payload),
            failure_reason=failure_reason,
            failed_at=datetime.now(timezone.utc).isoformat(),
            retry_count=0,
            resolved=False,
        )

        with self.get_session() as session:
            session.add(entry)
            session.commit()

    def get_pending_dead_letters(self, max_retries: int = 3) -> list[DeadLetterEntry]:
        """
        Get dead-letter entries eligible for retry.

        Ref: Methodology §4.3 — "entries where retry_count is below 3
        and failed_at is more than 5 minutes ago"
        """
        with self.get_session() as session:
            entries = (
                session.query(DeadLetterEntry)
                .filter(
                    DeadLetterEntry.retry_count < max_retries,
                    DeadLetterEntry.resolved == False,
                )
                .all()
            )
            # Detach from session before returning
            session.expunge_all()
            return entries

    def verify_hash(self, log_uuid: str) -> bool:
        """
        Verify SHA-256 hash integrity for a stored log entry.

        Ref: Methodology §1.5 — "If the hash of the stored raw_payload does not
        match the stored sha256_hash value, the log entry must be flagged as tampered."
        """
        import hashlib

        with self.get_session() as session:
            row = session.query(LogEntryRow).filter(LogEntryRow.log_uuid == log_uuid).first()
            if row is None:
                return False
            computed = hashlib.sha256(row.raw_payload.encode("utf-8")).hexdigest()
            return computed == row.sha256_hash

    # ─── Dead-Letter Queue Management Methods ──────────────────────────────
    # These methods are called by ingestion/dlq_retry.py
    # Ref: Methodology §4.3

    def get_pending_dlq_entries(
        self,
        max_retry_count: int = 3,
        min_age_seconds: int = 300,
    ) -> list[dict]:
        """
        Get DLQ entries eligible for retry.

        Returns entries where:
          - retry_count < max_retry_count
          - failed_at > min_age_seconds ago
          - resolved == False

        Ref: §4.3 — "entries where retry_count is below 3
        and failed_at is more than 5 minutes ago"
        """
        cutoff = datetime.now(timezone.utc).timestamp() - min_age_seconds

        with self.get_session() as session:
            entries = (
                session.query(DeadLetterEntry)
                .filter(
                    DeadLetterEntry.retry_count < max_retry_count,
                    DeadLetterEntry.resolved == False,
                )
                .all()
            )

            results = []
            for entry in entries:
                # Parse failed_at and check age
                try:
                    failed_dt = datetime.fromisoformat(
                        entry.failed_at.replace("Z", "+00:00")
                    )
                    if failed_dt.timestamp() > cutoff:
                        continue  # Too recent — skip
                except (ValueError, TypeError):
                    pass

                results.append({
                    "dlq_uuid": entry.dlq_uuid,
                    "work_type": entry.work_type,
                    "payload": entry.payload,
                    "failure_reason": entry.failure_reason,
                    "failed_at": entry.failed_at,
                    "retry_count": entry.retry_count,
                })

            return results

    def increment_dlq_retry(self, dlq_uuid: str) -> None:
        """Increment retry_count for a DLQ entry."""
        with self.get_session() as session:
            entry = (
                session.query(DeadLetterEntry)
                .filter(DeadLetterEntry.dlq_uuid == dlq_uuid)
                .first()
            )
            if entry:
                entry.retry_count += 1
                session.commit()

    def mark_dlq_resolved(self, dlq_uuid: str, resolved: bool = True) -> None:
        """
        Mark a DLQ entry as resolved (or unresolved).

        Ref: §4.3 — "the entry is marked as resolved=false
        and an analyst notification is sent"
        """
        with self.get_session() as session:
            entry = (
                session.query(DeadLetterEntry)
                .filter(DeadLetterEntry.dlq_uuid == dlq_uuid)
                .first()
            )
            if entry:
                entry.resolved = resolved
                session.commit()

    def write_to_dlq(
        self,
        work_type: str,
        payload: dict,
        failure_reason: str,
    ) -> str:
        """
        Write a failed work item to the DLQ. Returns the dlq_uuid.

        This is an alias for store_dead_letter that returns the UUID
        for tracking.
        """
        dlq_uuid = str(uuid.uuid4())
        entry = DeadLetterEntry(
            dlq_uuid=dlq_uuid,
            work_type=work_type,
            payload=json.dumps(payload),
            failure_reason=failure_reason,
            failed_at=datetime.now(timezone.utc).isoformat(),
            retry_count=0,
            resolved=False,
        )

        with self.get_session() as session:
            session.add(entry)
            session.commit()

        logger.warning(
            f"DLQ entry created: {dlq_uuid} (type={work_type}, reason={failure_reason})"
        )
        return dlq_uuid

