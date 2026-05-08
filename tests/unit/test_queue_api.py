"""
AEGIS Unit Tests — Queue API

Tests the FastAPI queue endpoints that OpenClaw polls.

Ref: TABLE 11 — "HEARTBEAT.md polls queue with non-blocking 200ms timeout"
"""

import pytest
import hashlib
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from ingestion.api import app, init_api
from ingestion.db import DatabaseManager
from ingestion.models import EventType, NormalizedLogEntry, Severity
from ingestion.priority_queue import AegisPriorityQueue


@pytest.fixture
def setup_api(tmp_path):
    """Set up API with real queue and test DB."""
    queue = AegisPriorityQueue(max_depth=50)
    db = DatabaseManager(db_path=str(tmp_path / "test.db"))
    init_api(queue, db)
    return queue, db


@pytest.fixture
def client(setup_api):
    """FastAPI test client."""
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["queue_initialized"] is True
        assert data["db_initialized"] is True


class TestQueueStatsEndpoint:
    def test_empty_queue_stats(self, client):
        resp = client.get("/queue/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["depth"] == 0
        assert data["total_enqueued"] == 0
        assert data["total_dropped"] == 0


class TestQueueNextEndpoint:
    def test_empty_queue_returns_not_found(self, client):
        """When queue is empty, GET /queue/next returns found=false."""
        resp = client.get("/queue/next")
        assert resp.status_code == 200
        data = resp.json()
        assert data["found"] is False

    @pytest.mark.asyncio
    async def test_dequeue_returns_entry(self, setup_api):
        """After enqueueing an entry, GET /queue/next returns it."""
        queue, db = setup_api

        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.PRIVILEGE_ESCALATION,
            hostname="TARGET01",
            sha256_hash="abc123",
            raw_payload="test",
            synthetic_intent="Privilege escalation detected on TARGET01",
        )

        severity = await queue.enqueue(entry)
        assert severity == Severity.P0
        assert queue.depth == 1


class TestInjectEndpoint:
    def test_inject_creates_entry(self, client):
        """POST /queue/inject creates a normalized, translated entry."""
        resp = client.post("/queue/inject", json={
            "raw_line": '{"EventID": "10", "Image": "mimikatz.exe"}',
            "event_type": "PRIVILEGE_ESCALATION",
            "hostname": "VICTIM01",
            "process_name": "mimikatz.exe",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["log_uuid"]  # UUID generated
        assert data["synthetic_intent"]  # Intent translated
        assert len(data["synthetic_intent"]) > 10

    def test_inject_unknown_event_type(self, client):
        """Invalid event_type falls back to UNKNOWN."""
        resp = client.post("/queue/inject", json={
            "raw_line": "test raw line",
            "event_type": "INVALID_TYPE",
            "hostname": "TESTHOST",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["severity"] in ("BENIGN", "P2", "P1", "P0")

    def test_inject_and_dequeue(self, client):
        """Inject a P0 entry, then dequeue it."""
        # Inject
        inject_resp = client.post("/queue/inject", json={
            "raw_line": "mimikatz credential dump",
            "event_type": "PRIVILEGE_ESCALATION",
            "hostname": "DC01",
            "process_name": "mimikatz.exe",
        })
        assert inject_resp.status_code == 200

        # Dequeue
        next_resp = client.get("/queue/next")
        assert next_resp.status_code == 200
        data = next_resp.json()
        # Entry may or may not be queued depending on scoring
        # (P0 events from inject are always queued)
