"""
AEGIS Unit Tests — Priority Queue Scoring

Tests the heuristic scoring function for P0/P1/P2/BENIGN classification.

Ref: Methodology §5.1 — "the priority score assigned by the heuristic function
matches the expected classification"
"""

import pytest

from ingestion.models import EventType, NormalizedLogEntry, Severity
from ingestion.priority_queue import compute_severity


class TestPriorityScoring:
    """
    Ref: Methodology §1.6 — Priority scoring rules
    """

    def test_privilege_escalation_is_p0(self):
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.PRIVILEGE_ESCALATION,
            hostname="TARGET01",
            sha256_hash="abc",
            raw_payload="test",
        )
        severity, priority = compute_severity(entry)
        assert severity == Severity.P0
        assert priority == 0

    def test_exfiltration_hint_is_p0(self):
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.EXFILTRATION_HINT,
            hostname="TARGET01",
            sha256_hash="abc",
            raw_payload="test",
        )
        severity, _ = compute_severity(entry)
        assert severity == Severity.P0

    def test_lateral_movement_is_p0(self):
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.LATERAL_MOVEMENT_HINT,
            hostname="TARGET01",
            sha256_hash="abc",
            raw_payload="test",
        )
        severity, _ = compute_severity(entry)
        assert severity == Severity.P0

    def test_auth_failure_burst_is_p0(self):
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.AUTHENTICATION_FAILURE_BURST,
            hostname="TARGET01",
            sha256_hash="abc",
            raw_payload="test",
        )
        severity, _ = compute_severity(entry)
        assert severity == Severity.P0

    def test_web_shell_process_creation_is_p1(self):
        """Ref: Methodology §1.6 — 'PROCESS_CREATION with a web server parent receives P1'"""
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.PROCESS_CREATION,
            hostname="WEBSERVER01",
            sha256_hash="abc",
            raw_payload="test",
            process_name="cmd.exe",
            parent_process_name="apache2",
        )
        severity, priority = compute_severity(entry)
        assert severity == Severity.P1
        assert priority == 1

    def test_network_c2_port_is_p1(self):
        """Ref: Methodology §1.6 — 'NETWORK_CONNECTION to external IPs on unusual ports receives P1'"""
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.NETWORK_CONNECTION,
            hostname="WORKSTATION01",
            sha256_hash="abc",
            raw_payload="test",
            dest_port=4444,
        )
        severity, priority = compute_severity(entry)
        assert severity == Severity.P1
        assert priority == 1

    def test_mitre_hint_is_p2(self):
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.FILE_WRITE,
            hostname="TARGET01",
            sha256_hash="abc",
            raw_payload="test",
            mitre_technique_hint="T1543",
        )
        severity, _ = compute_severity(entry)
        assert severity == Severity.P2

    def test_benign_network_connection(self):
        """Normal network connection on standard port → BENIGN"""
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.NETWORK_CONNECTION,
            hostname="WORKSTATION01",
            sha256_hash="abc",
            raw_payload="test",
            dest_port=443,
        )
        severity, _ = compute_severity(entry)
        assert severity == Severity.BENIGN

    def test_benign_auth_success(self):
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.AUTHENTICATION_SUCCESS,
            hostname="DC01",
            sha256_hash="abc",
            raw_payload="test",
        )
        severity, _ = compute_severity(entry)
        assert severity == Severity.BENIGN

    def test_dns_high_entropy_is_p2(self):
        """DNS with high entropy intent → P2"""
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.DNS_QUERY,
            hostname="WORKSTATION05",
            sha256_hash="abc",
            raw_payload="test",
            synthetic_intent="WORKSTATION05 queried DNS... Domain has high entropy — possible DNS tunneling",
        )
        severity, _ = compute_severity(entry)
        assert severity == Severity.P2
