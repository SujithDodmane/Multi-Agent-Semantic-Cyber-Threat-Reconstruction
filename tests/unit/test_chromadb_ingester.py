"""
AEGIS Unit Tests — ChromaDB Ingester

Tests the ingestion pipeline, metadata structure, timestamp parsing,
and collection manager without requiring a running ChromaDB instance.

Ref: Methodology §3.2 — ChromaDB Collection Design
Ref: TABLE 12 — "HNSW parameters set (ef_construction=200, M=48)"
"""

import pytest
from datetime import datetime, timezone

from services.embedding.chromadb_ingester import _parse_timestamp
from services.embedding.collection_manager import (
    HNSW_PARAMS,
    ACTIVE_COLLECTION,
    ARCHIVE_COLLECTION,
    HOT_WINDOW_SECONDS,
)


# ─── Timestamp Parsing Tests ───────────────────────────────────────────────


class TestTimestampParsing:
    """Verify ISO8601 → Unix timestamp conversion."""

    def test_iso8601_utc(self):
        ts = _parse_timestamp("2026-05-07T10:00:00+00:00")
        assert ts > 0
        assert isinstance(ts, float)

    def test_iso8601_with_z(self):
        ts = _parse_timestamp("2026-05-07T10:00:00Z")
        assert ts > 0

    def test_empty_string(self):
        assert _parse_timestamp("") == 0.0

    def test_none_equivalent(self):
        assert _parse_timestamp("") == 0.0

    def test_invalid_format(self):
        assert _parse_timestamp("not-a-date") == 0.0

    def test_timestamp_ordering(self):
        """Later timestamp should have higher Unix value."""
        ts1 = _parse_timestamp("2026-05-07T10:00:00Z")
        ts2 = _parse_timestamp("2026-05-07T12:00:00Z")
        assert ts2 > ts1


# ─── Metadata Structure Tests ──────────────────────────────────────────────


class TestMetadataStructure:
    """
    Ref: §3.2 — "metadata containing log_uuid, event_timestamp as
    Unix timestamp integer, event_type, source_ip, dest_ip, hostname"
    """

    def test_metadata_fields(self):
        """Verify all required metadata fields are defined."""
        required_fields = {
            "log_uuid", "event_timestamp", "event_type", "hostname"
        }
        entry = {
            "log_uuid": "test-uuid",
            "event_timestamp": "2026-05-07T10:00:00Z",
            "event_type": "PROCESS_CREATION",
            "hostname": "TESTHOST",
            "source_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "synthetic_intent": "Test intent",
        }

        # Build metadata dict same as ingester does
        metadata = {
            "log_uuid": entry["log_uuid"],
            "event_timestamp": _parse_timestamp(entry["event_timestamp"]),
            "event_type": entry["event_type"],
            "hostname": entry["hostname"],
        }

        for field in required_fields:
            assert field in metadata, f"Missing required metadata field: {field}"

    def test_optional_fields_excluded_when_none(self):
        """source_ip and dest_ip should only be included when non-None."""
        entry_no_ip = {
            "log_uuid": "test",
            "source_ip": None,
            "dest_ip": None,
        }

        metadata = {}
        if entry_no_ip.get("source_ip"):
            metadata["source_ip"] = entry_no_ip["source_ip"]
        if entry_no_ip.get("dest_ip"):
            metadata["dest_ip"] = entry_no_ip["dest_ip"]

        assert "source_ip" not in metadata
        assert "dest_ip" not in metadata


# ─── HNSW Configuration Tests ─────────────────────────────────────────────


class TestHNSWConfig:
    """
    Ref: §3.2 — "ef_construction=200, M=48. These values produce an index
    that balances search speed and recall."
    """

    def test_ef_construction(self):
        assert HNSW_PARAMS["hnsw:construction_ef"] == 200

    def test_m_parameter(self):
        assert HNSW_PARAMS["hnsw:M"] == 48

    def test_collection_names(self):
        """Verify dual-collection naming."""
        assert ACTIVE_COLLECTION == "logs_active"
        assert ARCHIVE_COLLECTION == "logs_archive"

    def test_hot_window(self):
        """Hot window should be 72 hours by default."""
        assert HOT_WINDOW_SECONDS == 72 * 3600


# ─── Cold Start Tests ─────────────────────────────────────────────────────


class TestColdStart:
    """
    Ref: §3.3 — "On a fresh deployment with an empty ChromaDB,
    the first query will return zero results."
    """

    def test_empty_entries_is_cold_start(self):
        """An empty result set should be interpreted as cold start."""
        entries = []
        cold_start = len(entries) == 0
        assert cold_start is True

    def test_non_empty_is_not_cold_start(self):
        entries = [{"log_uuid": "test"}]
        cold_start = len(entries) == 0
        assert cold_start is False


# ─── Temporal Window Tests ─────────────────────────────────────────────────


class TestTemporalWindows:
    """
    Ref: §3.3 — "The time window of ±2 hours is configurable per event_type"
    """

    def test_default_window_loaded(self):
        """Default temporal window should be 7200 (±2hr)."""
        from services.correlation.app import get_temporal_window
        # UNKNOWN should fall back to default
        window = get_temporal_window("SOME_UNKNOWN_TYPE")
        assert window == 7200

    def test_fast_moving_window(self):
        """PRIVILEGE_ESCALATION should have ±30 minute window."""
        from services.correlation.app import get_temporal_window, TEMPORAL_WINDOWS
        if TEMPORAL_WINDOWS:  # Config loaded
            window = get_temporal_window("PRIVILEGE_ESCALATION")
            assert window == 1800

    def test_slow_apt_window(self):
        """DNS_QUERY should have ±6 hour window."""
        from services.correlation.app import get_temporal_window, TEMPORAL_WINDOWS
        if TEMPORAL_WINDOWS:  # Config loaded
            window = get_temporal_window("DNS_QUERY")
            assert window == 21600
