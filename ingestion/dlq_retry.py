"""
AEGIS — Dead-Letter Queue Retry Task

Background asyncio coroutine that retries failed work items from the
dead-letter queue. Runs every 5 minutes.

Ref: Methodology §4.3 — Dead-Letter Queue Management
  - Check every 5 minutes
  - Re-submit at P1 if retry_count < 3 and failed_at > 5 min ago
  - After 3 retries: mark resolved=false, send analyst notification
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger("aegis.dlq_retry")

# ─── Configuration ─────────────────────────────────────────────────────────

RETRY_INTERVAL_SECONDS = 300  # 5 minutes
MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 300  # Wait 5 min after failure before retrying


async def dlq_retry_loop(db_manager, priority_queue=None):
    """
    Background task: check dead-letter queue every 5 minutes and retry
    eligible entries.

    Ref: §4.3 — "A background task running as an asyncio coroutine checks
    the dead-letter queue every 5 minutes."

    Args:
        db_manager: DatabaseManager instance for SQLite access
        priority_queue: AegisPriorityQueue instance for re-submission
    """
    logger.info(
        f"DLQ retry loop started (interval: {RETRY_INTERVAL_SECONDS}s, "
        f"max retries: {MAX_RETRIES})"
    )

    while True:
        await asyncio.sleep(RETRY_INTERVAL_SECONDS)

        try:
            retried, escalated = await _process_dlq(db_manager, priority_queue)
            if retried > 0 or escalated > 0:
                logger.info(
                    f"DLQ cycle: retried={retried}, escalated={escalated}"
                )
        except Exception as e:
            logger.error(f"DLQ retry loop error: {e}")


async def _process_dlq(db_manager, priority_queue) -> tuple[int, int]:
    """
    Process one cycle of the dead-letter queue.

    Returns (retried_count, escalated_count).
    """
    retried = 0
    escalated = 0

    try:
        # Get pending DLQ entries
        entries = db_manager.get_pending_dlq_entries(
            max_retry_count=MAX_RETRIES,
            min_age_seconds=RETRY_DELAY_SECONDS,
        )

        for entry in entries:
            dlq_uuid = entry.get("dlq_uuid", "")
            retry_count = entry.get("retry_count", 0)
            work_type = entry.get("work_type", "UNKNOWN")
            payload = entry.get("payload", "{}")

            if retry_count >= MAX_RETRIES:
                # Ref: §4.3 — "After 3 total retry attempts, the entry is
                # marked as resolved=false and an analyst notification is sent"
                db_manager.mark_dlq_resolved(dlq_uuid, resolved=False)
                _notify_analyst_manual_review(entry)
                escalated += 1
                logger.warning(
                    f"DLQ {dlq_uuid}: max retries exceeded — "
                    f"escalating to analyst (work_type={work_type})"
                )
                continue

            # Re-submit at P1 priority
            # Ref: §4.3 — "the task re-submits the work item to the
            # priority queue at P1 priority"
            if priority_queue is not None:
                try:
                    payload_dict = json.loads(payload) if isinstance(payload, str) else payload
                    # Reconstruct a minimal NormalizedLogEntry for re-queuing
                    from ingestion.models import NormalizedLogEntry, EventType
                    reentry = NormalizedLogEntry(
                        log_uuid=payload_dict.get("log_uuid", dlq_uuid),
                        event_timestamp=payload_dict.get("event_timestamp", ""),
                        event_type=EventType(payload_dict.get("event_type", "UNKNOWN")),
                        hostname=payload_dict.get("hostname", "unknown"),
                        sha256_hash=payload_dict.get("sha256_hash", "dlq_retry"),
                        raw_payload=payload_dict.get("raw_payload", ""),
                        synthetic_intent=payload_dict.get("synthetic_intent", ""),
                    )
                    await priority_queue.enqueue(reentry, force_priority=1)  # P1
                except Exception as e:
                    logger.error(f"DLQ {dlq_uuid}: re-queue failed: {e}")
                    continue

            # Increment retry count
            db_manager.increment_dlq_retry(dlq_uuid)
            retried += 1
            logger.info(
                f"DLQ {dlq_uuid}: retried (attempt {retry_count + 1}/{MAX_RETRIES})"
            )

    except Exception as e:
        logger.error(f"DLQ processing error: {e}")

    return retried, escalated


def _notify_analyst_manual_review(entry: dict):
    """
    Send analyst notification for manually unresolvable DLQ entries.

    Ref: §4.3 — "notification includes the log_uuid of the original log entry
    so the analyst can retrieve it from SQLite directly"

    TODO: Wire to Telegram/Discord Protocol Adapter in Phase 4.
    """
    log_uuid = entry.get("payload", {})
    if isinstance(log_uuid, str):
        try:
            log_uuid = json.loads(log_uuid).get("log_uuid", "unknown")
        except (json.JSONDecodeError, AttributeError):
            log_uuid = "unknown"

    logger.critical(
        f"⚠️ ANALYST REVIEW REQUIRED — DLQ entry exhausted retries. "
        f"Work type: {entry.get('work_type', 'UNKNOWN')}, "
        f"Original log_uuid: {log_uuid}, "
        f"Failure reason: {entry.get('failure_reason', 'unknown')}"
    )
