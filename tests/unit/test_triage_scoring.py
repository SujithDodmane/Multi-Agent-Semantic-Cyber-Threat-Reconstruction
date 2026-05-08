"""
AEGIS Unit Tests — Triage Scoring Engine

Validates the heuristic decision tree against all conditions
from the methodology and threat_lists.yaml.

Ref: Methodology §2.2 — Triage SKILL.md Implementation Logic
Ref: TABLE 11 — "Triage SKILL.md flag conditions cover all heuristic categories"
"""

import pytest
from pathlib import Path

from ingestion.models import EventType, NormalizedLogEntry
from services.orchestrator.triage_scorer import TriageScorer


@pytest.fixture
def scorer():
    """Scorer loaded with the canonical threat_lists.yaml."""
    config_path = Path(__file__).parent.parent.parent / "openclaw" / "config" / "threat_lists.yaml"
    return TriageScorer(config_path=config_path)


@pytest.fixture
def default_scorer():
    """Scorer with built-in defaults (no YAML)."""
    return TriageScorer()


def _make_entry(**kwargs) -> NormalizedLogEntry:
    """Helper to create a NormalizedLogEntry with defaults."""
    defaults = {
        "event_timestamp": "2026-05-07T10:00:00Z",
        "event_type": EventType.UNKNOWN,
        "hostname": "TESTHOST",
        "sha256_hash": "abc123",
        "raw_payload": "test",
    }
    defaults.update(kwargs)
    return NormalizedLogEntry(**defaults)


# ─── Individual Condition Tests ─────────────────────────────────────────────


class TestCondition1_DangerousProcess:
    """process_name in dangerous list → +40"""

    def test_mimikatz(self, scorer):
        entry = _make_entry(process_name="mimikatz.exe")
        result = scorer.score(entry)
        assert result["score"] >= 40
        assert any("dangerous_process" in f for f in result["heuristic_flags"])

    def test_procdump(self, scorer):
        entry = _make_entry(process_name="procdump.exe")
        result = scorer.score(entry)
        assert result["score"] >= 40

    def test_psexec(self, scorer):
        entry = _make_entry(process_name="psexec.exe")
        result = scorer.score(entry)
        assert result["score"] >= 40

    def test_rubeus(self, scorer):
        entry = _make_entry(process_name="rubeus.exe")
        result = scorer.score(entry)
        assert result["score"] >= 40

    def test_safe_process(self, scorer):
        entry = _make_entry(process_name="notepad.exe")
        result = scorer.score(entry)
        assert not any("dangerous_process" in f for f in result["heuristic_flags"])


class TestCondition2_WebShell:
    """Web server parent + cmd child → +35"""

    def test_apache_cmd(self, scorer):
        entry = _make_entry(
            parent_process_name="apache2",
            process_name="cmd.exe",
        )
        result = scorer.score(entry)
        assert result["score"] >= 35
        assert any("webshell" in f for f in result["heuristic_flags"])

    def test_nginx_powershell(self, scorer):
        entry = _make_entry(
            parent_process_name="nginx",
            process_name="powershell.exe",
        )
        result = scorer.score(entry)
        assert result["score"] >= 35

    def test_w3wp_bash(self, scorer):
        entry = _make_entry(
            parent_process_name="w3wp.exe",
            process_name="bash",
        )
        result = scorer.score(entry)
        assert result["score"] >= 35

    def test_explorer_cmd_not_webshell(self, scorer):
        """explorer.exe → cmd.exe is NOT a web shell."""
        entry = _make_entry(
            parent_process_name="explorer.exe",
            process_name="cmd.exe",
        )
        result = scorer.score(entry)
        assert not any("webshell" in f for f in result["heuristic_flags"])


class TestCondition3_C2Port:
    """dest_port in C2 list → +30"""

    def test_port_4444(self, scorer):
        entry = _make_entry(dest_port=4444)
        result = scorer.score(entry)
        assert result["score"] >= 30
        assert any("c2_port" in f for f in result["heuristic_flags"])

    def test_port_5555(self, scorer):
        entry = _make_entry(dest_port=5555)
        result = scorer.score(entry)
        assert result["score"] >= 30

    def test_port_1337(self, scorer):
        entry = _make_entry(dest_port=1337)
        result = scorer.score(entry)
        assert result["score"] >= 30

    def test_port_443_safe(self, scorer):
        """Port 443 (HTTPS) is NOT a C2 port."""
        entry = _make_entry(dest_port=443)
        result = scorer.score(entry)
        assert not any("c2_port" in f for f in result["heuristic_flags"])


class TestCondition4_CriticalEventType:
    """PRIVILEGE_ESCALATION or EXFILTRATION_HINT → +50"""

    def test_privilege_escalation(self, scorer):
        entry = _make_entry(event_type=EventType.PRIVILEGE_ESCALATION)
        result = scorer.score(entry)
        assert result["score"] >= 50
        assert any("critical_event" in f for f in result["heuristic_flags"])

    def test_exfiltration_hint(self, scorer):
        entry = _make_entry(event_type=EventType.EXFILTRATION_HINT)
        result = scorer.score(entry)
        assert result["score"] >= 50

    def test_process_creation_not_critical(self, scorer):
        entry = _make_entry(event_type=EventType.PROCESS_CREATION)
        result = scorer.score(entry)
        assert not any("critical_event" in f for f in result["heuristic_flags"])


class TestCondition5_IpHistorical:
    """IP seen in activity → +20"""

    def test_source_ip_seen(self, scorer):
        entry = _make_entry(source_ip="10.0.0.5")
        result = scorer.score(entry, ip_activity_lookup={"10.0.0.5": 3})
        assert result["score"] >= 20
        assert "ip_historical_correlation" in result["heuristic_flags"]

    def test_dest_ip_seen(self, scorer):
        entry = _make_entry(dest_ip="192.168.1.100")
        result = scorer.score(entry, ip_activity_lookup={"192.168.1.100": 5})
        assert result["score"] >= 20

    def test_no_ip_history(self, scorer):
        entry = _make_entry(source_ip="10.0.0.5")
        result = scorer.score(entry, ip_activity_lookup={})
        assert "ip_historical_correlation" not in result["heuristic_flags"]


# ─── Severity Threshold Boundary Tests ──────────────────────────────────────


class TestSeverityThresholds:
    """
    Ref: Methodology §2.2:
    0-20=BENIGN, 21-40=P2, 41-60=P1, 61+=P0
    """

    def test_score_0_benign(self, scorer):
        entry = _make_entry(process_name="notepad.exe")
        result = scorer.score(entry)
        assert result["severity"] == "BENIGN"
        assert result["anomaly_detected"] is False
        assert result["correlation_required"] is False

    def test_score_30_p2(self, scorer):
        """C2 port alone = 30 → P2"""
        entry = _make_entry(dest_port=4444)
        result = scorer.score(entry)
        assert result["severity"] == "P2"
        assert result["correlation_required"] is False

    def test_score_40_p2(self, scorer):
        """Dangerous process alone = 40 → P2 (below P1 threshold of 41)"""
        entry = _make_entry(process_name="mimikatz.exe")
        result = scorer.score(entry)
        assert result["severity"] == "P2"

    def test_score_50_p1(self, scorer):
        """Critical event type = 50 → P1"""
        entry = _make_entry(event_type=EventType.PRIVILEGE_ESCALATION)
        result = scorer.score(entry)
        assert result["severity"] == "P1"
        assert result["correlation_required"] is True

    def test_score_70_p0(self, scorer):
        """Dangerous process (40) + C2 port (30) = 70 → P0"""
        entry = _make_entry(process_name="mimikatz.exe", dest_port=4444)
        result = scorer.score(entry)
        assert result["severity"] == "P0"
        assert result["correlation_required"] is True
        assert result["score"] >= 61

    def test_score_75_p0_webshell_plus_dangerous(self, scorer):
        """Web shell (35) + dangerous process (40) = 75 → P0"""
        entry = _make_entry(
            parent_process_name="apache2",
            process_name="cmd.exe",
            # cmd.exe is not in the dangerous list by default,
            # but webshell (35) + C2 port (30) would be 65 → P0
            dest_port=4444,
        )
        result = scorer.score(entry)
        assert result["severity"] == "P0"

    def test_correlation_required_for_p0_and_p1(self, scorer):
        """P0 and P1 require correlation; P2 and BENIGN do not."""
        # P0
        entry_p0 = _make_entry(process_name="mimikatz.exe", dest_port=4444)
        assert scorer.score(entry_p0)["correlation_required"] is True

        # P1
        entry_p1 = _make_entry(event_type=EventType.PRIVILEGE_ESCALATION)
        assert scorer.score(entry_p1)["correlation_required"] is True

        # P2
        entry_p2 = _make_entry(dest_port=4444)
        assert scorer.score(entry_p2)["correlation_required"] is False

        # BENIGN
        entry_benign = _make_entry(process_name="notepad.exe")
        assert scorer.score(entry_benign)["correlation_required"] is False


# ─── Config Loading Tests ───────────────────────────────────────────────────


class TestConfigLoading:
    def test_loads_yaml_config(self, scorer):
        """Verify threat lists loaded from YAML."""
        assert "mimikatz" in scorer.dangerous_processes or "mimikatz.exe" in scorer.dangerous_processes
        assert 4444 in scorer.c2_ports
        assert 5555 in scorer.c2_ports

    def test_default_fallback(self, default_scorer):
        """Verify defaults work without YAML."""
        assert len(default_scorer.dangerous_processes) > 0
        assert len(default_scorer.c2_ports) > 0
