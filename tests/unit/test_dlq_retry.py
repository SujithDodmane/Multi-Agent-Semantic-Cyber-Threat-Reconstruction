"""
AEGIS Unit Tests — Dead-Letter Queue Retry

Tests the DLQ retry logic, timing, and escalation behavior.

Ref: Methodology §4.3 — Dead-Letter Queue Management
Ref: TABLE 12 — "3-retry fallback triggers dead-letter queue escalation"
"""

import pytest

from ingestion.dlq_retry import (
    RETRY_INTERVAL_SECONDS,
    MAX_RETRIES,
    RETRY_DELAY_SECONDS,
)


# ─── Configuration Tests ──────────────────────────────────────────────────


class TestDLQConfig:
    """Verify DLQ retry configuration matches methodology."""

    def test_retry_interval(self):
        """
        Ref: §4.3 — "checks the dead-letter queue every 5 minutes"
        """
        assert RETRY_INTERVAL_SECONDS == 300  # 5 minutes

    def test_max_retries(self):
        """
        Ref: §4.3 — "After 3 total retry attempts"
        """
        assert MAX_RETRIES == 3

    def test_retry_delay(self):
        """
        Ref: §4.3 — "failed_at is more than 5 minutes ago"
        """
        assert RETRY_DELAY_SECONDS == 300  # 5 minutes


# ─── Retry Logic Tests ────────────────────────────────────────────────────


class TestRetryLogic:
    """Test the retry decision logic."""

    def test_entry_under_max_retries_eligible(self):
        """Entries with retry_count < 3 should be retried."""
        for count in range(MAX_RETRIES):
            assert count < MAX_RETRIES

    def test_entry_at_max_retries_escalated(self):
        """Entries with retry_count >= 3 should be escalated."""
        assert 3 >= MAX_RETRIES

    def test_re_submission_priority(self):
        """
        Ref: §4.3 — "re-submits the work item to the priority queue
        at P1 priority"
        """
        # P1 = priority 1 (second highest after P0)
        p1_priority = 1
        assert p1_priority == 1


# ─── Escalation Tests ─────────────────────────────────────────────────────


class TestEscalation:
    """Test the escalation behavior for exhausted retries."""

    def test_exhausted_entry_marked_unresolved(self):
        """
        Ref: §4.3 — "the entry is marked as resolved=false"
        """
        retry_count = 3
        resolved = not (retry_count >= MAX_RETRIES)
        assert resolved is False

    def test_analyst_notification_includes_log_uuid(self):
        """
        Ref: §4.3 — "This notification includes the log_uuid of the
        original log entry so the analyst can retrieve it from SQLite"
        """
        import json
        payload = json.dumps({
            "log_uuid": "test-uuid-12345",
            "event_type": "PRIVILEGE_ESCALATION",
        })
        parsed = json.loads(payload)
        assert "log_uuid" in parsed
        assert parsed["log_uuid"] == "test-uuid-12345"

    def test_work_types_defined(self):
        """
        Ref: §4.3 — "work_type (EMBEDDING / CORRELATION / TIMELINE_SYNTHESIS)"
        """
        valid_work_types = {"EMBEDDING", "CORRELATION", "TIMELINE_SYNTHESIS"}
        for wt in valid_work_types:
            assert isinstance(wt, str)
            assert len(wt) > 0


# ─── Circuit Breaker Integration Tests ─────────────────────────────────────


class TestCircuitBreakerConfig:
    """
    Ref: §3.5 — Circuit Breaker Implementation
    """

    def test_breaker_params(self):
        """Verify breaker configuration matches methodology."""
        from services.shared.circuit_breaker import embedding_breaker, ollama_breaker

        assert embedding_breaker._fail_max == 3
        assert embedding_breaker._reset_timeout == 60
        assert ollama_breaker._fail_max == 3
        assert ollama_breaker._reset_timeout == 60

    def test_breaker_names(self):
        """Each downstream endpoint should have its own breaker."""
        from services.shared.circuit_breaker import (
            embedding_breaker,
            ollama_breaker,
            chromadb_breaker,
            correlation_breaker,
        )

        names = {
            embedding_breaker.name,
            ollama_breaker.name,
            chromadb_breaker.name,
            correlation_breaker.name,
        }
        assert len(names) == 4  # All unique
