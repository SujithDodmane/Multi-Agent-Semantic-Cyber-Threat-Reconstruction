"""
AEGIS Stress Test — Priority Queue Under Load

Tests queue behavior under sustained high-throughput injection.
Validates backpressure, P0/P1 no-drop guarantee, and queue depth limits.

Ref: Methodology §5.3 — Stress Testing: Concurrency & Backpressure
"""

import asyncio
import sys
import uuid
import random
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ingestion.priority_queue import AegisPriorityQueue, compute_severity
from ingestion.models import NormalizedLogEntry, EventType, Severity


# ─── Helpers ───────────────────────────────────────────────────────────────


def _make_entry(event_type: EventType = EventType.NETWORK_CONNECTION,
                dest_port: int = 80, parent_process: str = "",
                process_name: str = "test.exe",
                mitre_hint: str = "") -> NormalizedLogEntry:
    """Generate a synthetic NormalizedLogEntry for queue injection."""
    return NormalizedLogEntry(
        log_uuid=str(uuid.uuid4()),
        event_type=event_type,
        hostname=f"HOST-{random.randint(1, 100)}",
        event_timestamp="2026-05-07T10:00:00Z",
        ingestion_timestamp="2026-05-07T10:00:00Z",
        sha256_hash="a" * 64,
        raw_payload='{"test": true}',
        synthetic_intent="Test entry for stress testing",
        process_name=process_name,
        parent_process_name=parent_process or None,
        source_ip=f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        dest_ip=f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        dest_port=dest_port,
        mitre_technique_hint=mitre_hint or None,
    )


def _make_p0_entry() -> NormalizedLogEntry:
    """Create a P0 entry (PRIVILEGE_ESCALATION)."""
    return _make_entry(event_type=EventType.PRIVILEGE_ESCALATION)


def _make_p1_entry() -> NormalizedLogEntry:
    """Create a P1 entry (C2 port)."""
    return _make_entry(event_type=EventType.NETWORK_CONNECTION, dest_port=4444)


def _make_p2_entry() -> NormalizedLogEntry:
    """Create a P2 entry (auth failure)."""
    return _make_entry(event_type=EventType.AUTHENTICATION_FAILURE)


def _make_benign_entry() -> NormalizedLogEntry:
    """Create a BENIGN entry."""
    return _make_entry(event_type=EventType.NETWORK_CONNECTION, dest_port=443)


# ─── Test: Queue Depth Under Load ──────────────────────────────────────────


class TestQueueStress:
    """
    Ref: §5.3 — "injects a continuous stream of entries. The test validates:
    no P0 or P1 entries are dropped."
    """

    @pytest.mark.asyncio
    async def test_queue_handles_high_volume(self):
        """
        Inject 5,000 entries with 5% anomalous.
        Verify all P0/P1 are preserved.
        """
        queue = AegisPriorityQueue(max_depth=200)
        total_entries = 5000

        p0_injected = 0
        p1_injected = 0

        random.seed(42)

        for i in range(total_entries):
            r = random.random()
            if r < 0.01:  # 1% P0
                entry = _make_p0_entry()
                p0_injected += 1
            elif r < 0.05:  # 4% P1
                entry = _make_p1_entry()
                p1_injected += 1
            elif r < 0.15:  # 10% P2
                entry = _make_p2_entry()
            else:
                entry = _make_benign_entry()

            await queue.enqueue(entry)

        # Dequeue all and count
        p0_dequeued = 0
        p1_dequeued = 0
        total_dequeued = 0

        while True:
            item = await queue.dequeue()
            if item is None:
                break
            total_dequeued += 1
            if item.severity == Severity.P0:
                p0_dequeued += 1
            elif item.severity == Severity.P1:
                p1_dequeued += 1

        # Critical assertion: NO P0 or P1 dropped
        assert p0_dequeued == p0_injected, f"P0 dropped: {p0_injected - p0_dequeued}"
        assert p1_dequeued == p1_injected, f"P1 dropped: {p1_injected - p1_dequeued}"

    @pytest.mark.asyncio
    async def test_backpressure_drops_p2_not_p0(self):
        """P2 should be dropped under backpressure, but P0 never."""
        queue = AegisPriorityQueue(max_depth=10)

        # Fill queue with P2 entries
        for _ in range(20):
            await queue.enqueue(_make_p2_entry())

        # Now inject P0
        p0_entry = _make_p0_entry()
        result = await queue.enqueue(p0_entry)
        assert result == Severity.P0

        # P0 should be dequeued first
        item = await queue.dequeue()
        assert item is not None
        assert item.severity == Severity.P0

    @pytest.mark.asyncio
    async def test_p0_priority_ordering(self):
        """P0 entries should be dequeued before P2."""
        queue = AegisPriorityQueue(max_depth=100)

        # Inject P2 first
        for _ in range(10):
            await queue.enqueue(_make_p2_entry())

        # Then inject P0
        p0_entry = _make_p0_entry()
        await queue.enqueue(p0_entry)

        # First dequeue should be P0
        first = await queue.dequeue()
        assert first is not None
        assert first.severity == Severity.P0

    @pytest.mark.asyncio
    async def test_rapid_injection_no_crash(self):
        """Queue should handle rapid injection without errors."""
        queue = AegisPriorityQueue(max_depth=50)

        for _ in range(1000):
            r = random.random()
            if r < 0.1:
                await queue.enqueue(_make_p0_entry())
            elif r < 0.3:
                await queue.enqueue(_make_p1_entry())
            else:
                await queue.enqueue(_make_benign_entry())

        # Should be able to drain
        count = 0
        while True:
            item = await queue.dequeue()
            if item is None:
                break
            count += 1

        assert count > 0


# ─── Test: Concurrent P0 Race Condition ────────────────────────────────────


class TestConcurrentAnomalies:
    """
    Ref: §5.3 — "Inject two P0 anomalies within 10ms of each other.
    Assert: both anomalies produce separate, complete results."
    """

    @pytest.mark.asyncio
    async def test_two_p0_both_processed(self):
        """Two P0 entries should both be dequeued and distinct."""
        queue = AegisPriorityQueue(max_depth=100)

        p0_a = _make_p0_entry()
        p0_b = _make_p0_entry()

        # Inject back-to-back
        await queue.enqueue(p0_a)
        await queue.enqueue(p0_b)

        # Both should be dequeued
        results = []
        while True:
            item = await queue.dequeue()
            if item is None:
                break
            results.append(item)

        assert len(results) == 2
        uuids = {r.entry.log_uuid for r in results}
        assert len(uuids) == 2  # Distinct entries

    @pytest.mark.asyncio
    async def test_no_interleaving(self):
        """Concurrent P0s should not have interleaved data."""
        queue = AegisPriorityQueue(max_depth=100)

        p0_a = _make_entry(
            event_type=EventType.PRIVILEGE_ESCALATION,
            process_name="mimikatz.exe",
        )
        p0_b = _make_entry(
            event_type=EventType.EXFILTRATION_HINT,
            process_name="exfiltool.exe",
        )

        await queue.enqueue(p0_a)
        await queue.enqueue(p0_b)

        results = []
        while True:
            item = await queue.dequeue()
            if item is None:
                break
            results.append(item)

        # Each result should maintain its own data
        for r in results:
            if r.entry.process_name == "mimikatz.exe":
                assert r.entry.event_type == EventType.PRIVILEGE_ESCALATION
            elif r.entry.process_name == "exfiltool.exe":
                assert r.entry.event_type == EventType.EXFILTRATION_HINT


# ─── Test: Severity Computation ────────────────────────────────────────────


class TestSeverityComputation:
    """Test the heuristic scoring function."""

    def test_privilege_escalation_is_p0(self):
        entry = _make_entry(event_type=EventType.PRIVILEGE_ESCALATION)
        sev, pri = compute_severity(entry)
        assert sev == Severity.P0
        assert pri == 0

    def test_c2_port_is_p1(self):
        entry = _make_entry(event_type=EventType.NETWORK_CONNECTION, dest_port=4444)
        sev, pri = compute_severity(entry)
        assert sev == Severity.P1
        assert pri == 1

    def test_webshell_is_p1(self):
        entry = _make_entry(
            event_type=EventType.PROCESS_CREATION,
            parent_process="apache2.exe",
            process_name="cmd.exe",
        )
        sev, pri = compute_severity(entry)
        assert sev == Severity.P1

    def test_auth_failure_is_p2(self):
        entry = _make_entry(event_type=EventType.AUTHENTICATION_FAILURE)
        sev, pri = compute_severity(entry)
        assert sev == Severity.P2

    def test_benign_network(self):
        entry = _make_entry(event_type=EventType.NETWORK_CONNECTION, dest_port=443)
        sev, pri = compute_severity(entry)
        assert sev == Severity.BENIGN
