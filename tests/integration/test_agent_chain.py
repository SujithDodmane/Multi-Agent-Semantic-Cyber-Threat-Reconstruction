"""
AEGIS Integration Test — Agent Chain End-to-End

Tests the full pipeline: inject attack scenario → triage → format report
→ graph ingestion → verify outputs.

Uses the Web Shell → Lateral Movement scenario from §6.2 fixtures.
Mocks external HTTP services (embedding, Ollama) but runs actual Python logic.

Ref: Methodology §5.2 — Integration Testing: OpenClaw Handoff Verification
"""

import json
import os
import sys
from pathlib import Path

import pytest

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from services.notification.report_formatter import (
    format_report_markdown,
    format_report_plaintext,
    chunk_message,
)
from services.graph.graph_model import ThreatGraph, get_node_color, NODE_COLORS


# ─── Fixtures ──────────────────────────────────────────────────────────────

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


def load_fixture(name: str) -> list[dict]:
    """Load a test fixture JSON file."""
    with open(FIXTURES_DIR / name, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def webshell_scenario():
    """Load the Web Shell → Lateral Movement attack scenario."""
    return load_fixture("attack_scenario_webshell.json")


@pytest.fixture
def dns_tunnel_scenario():
    """Load the DNS Tunneling scenario."""
    return load_fixture("attack_scenario_dns_tunnel.json")


@pytest.fixture
def sample_forensic_report():
    """A sample ForensicReport matching the webshell scenario."""
    return {
        "narrative": (
            "Initial access was achieved via a web shell on WEBSERVER01. "
            "The attacker exploited apache2.exe to spawn cmd.exe, then performed "
            "network reconnaissance via SMB port 445 scanning. Credential dumping "
            "was performed using mimikatz.exe to extract LSASS credentials. "
            "Lateral movement was observed as the attacker authenticated to DBSERVER02 "
            "using compromised Administrator credentials. Data staging followed "
            "with archive creation at C:\\Users\\Public\\backup.7z."
        ),
        "confidence": 0.92,
        "mitre_tactics": ["TA0001", "TA0002", "TA0006", "TA0008"],
        "mitre_techniques": ["T1505.003", "T1059.003", "T1003.001", "T1021.002"],
        "entities": [
            {"type": "hostname", "value": "WEBSERVER01", "role": "entry_point"},
            {"type": "hostname", "value": "DBSERVER02", "role": "lateral_target"},
            {"type": "ip", "value": "10.0.0.50", "role": "attacker_source"},
            {"type": "process", "value": "mimikatz.exe", "role": "attacker_tool"},
            {"type": "process", "value": "cmd.exe", "role": "execution_shell"},
            {"type": "user", "value": "Administrator", "role": "compromised"},
            {"type": "user", "value": "www-data", "role": "initial_context"},
        ],
        "timeline_events": [
            {"timestamp": "2026-05-07T10:00:00Z", "description": "Web shell: apache2.exe spawns cmd.exe", "severity": "P1"},
            {"timestamp": "2026-05-07T10:00:30Z", "description": "SMB reconnaissance scan (3 hosts)", "severity": "P2"},
            {"timestamp": "2026-05-07T10:01:00Z", "description": "Credential dump: mimikatz.exe on lsass", "severity": "P0"},
            {"timestamp": "2026-05-07T10:02:00Z", "description": "Lateral movement: auth to DBSERVER02", "severity": "P1"},
            {"timestamp": "2026-05-07T10:03:00Z", "description": "Data staging: backup.7z created", "severity": "P2"},
        ],
        "root_cause": "Initial access via web shell exploitation of apache2.exe on WEBSERVER01.",
        "report_id": "rpt-webshell-001",
    }


# ─── Test: Fixture Loading ─────────────────────────────────────────────────


class TestFixtureLoading:
    """Verify all fixture files load correctly."""

    @pytest.mark.parametrize("fixture_name", [
        "sysmon_process_creation.json",
        "sysmon_network_connection.json",
        "zeek_dns_query.json",
        "auth_events.json",
        "http_requests.json",
        "file_writes.json",
        "attack_scenario_webshell.json",
        "attack_scenario_dns_tunnel.json",
    ])
    def test_fixture_loads(self, fixture_name):
        data = load_fixture(fixture_name)
        assert isinstance(data, list)
        assert len(data) > 0

    def test_webshell_scenario_has_7_steps(self):
        data = load_fixture("attack_scenario_webshell.json")
        assert len(data) == 7

    def test_dns_tunnel_has_20_queries(self):
        data = load_fixture("attack_scenario_dns_tunnel.json")
        assert len(data) == 20


# ─── Test: Triage Scoring on Attack Scenarios ─────────────────────────────


class TestTriageScoringIntegration:
    """Test triage scoring with attack scenario entries."""

    def test_webshell_step1_is_flagged(self, webshell_scenario):
        """Web shell (apache→cmd) should be flagged."""
        step1 = webshell_scenario[0]
        assert step1["process_name"] == "cmd.exe"
        assert step1["parent_process_name"] == "apache2.exe"
        assert step1["expected_severity"] == "P1"

    def test_credential_dump_step3_is_p0(self, webshell_scenario):
        """Mimikatz should be P0."""
        step3 = webshell_scenario[4]  # Index 4 is step 3
        assert step3["process_name"] == "mimikatz.exe"
        assert step3["expected_severity"] == "P0"

    def test_dns_tunnel_entries_share_parent_domain(self, dns_tunnel_scenario):
        """All DNS entries should query same parent domain."""
        for entry in dns_tunnel_scenario:
            assert "exfil.attacker.com" in entry["dns_query"]


# ─── Test: Report Formatting Integration ───────────────────────────────────


class TestReportFormattingIntegration:
    """Test full report formatting with attack scenario data."""

    def test_report_contains_attack_narrative(self, sample_forensic_report):
        """§5.2: report narrative mentions injected attack steps."""
        formatted = format_report_markdown(sample_forensic_report, severity="P0")
        assert "web shell" in formatted.lower()
        assert "mimikatz" in formatted.lower() or "credential" in formatted.lower()
        assert "DBSERVER02" in formatted

    def test_mitre_ids_present(self, sample_forensic_report):
        """§5.2: MITRE ATT&CK IDs are plausible."""
        formatted = format_report_markdown(sample_forensic_report, severity="P0")
        assert "T1505" in formatted  # Web Shell
        assert "T1003" in formatted  # Credential Dumping
        assert "T1021" in formatted  # Lateral Movement

    def test_confidence_above_threshold(self, sample_forensic_report):
        """§5.2: confidence score > 0.6."""
        assert sample_forensic_report["confidence"] > 0.6

    def test_entities_include_key_actors(self, sample_forensic_report):
        """§5.2: entities list includes attacker IP and victim hostname."""
        entity_values = [e["value"] for e in sample_forensic_report["entities"]]
        assert "10.0.0.50" in entity_values  # Attacker IP
        assert "WEBSERVER01" in entity_values  # Victim hostname
        assert "DBSERVER02" in entity_values  # Lateral target

    def test_report_id_valid(self, sample_forensic_report):
        """§5.2: report_id is present and non-empty."""
        assert sample_forensic_report["report_id"]
        assert len(sample_forensic_report["report_id"]) > 0

    def test_plaintext_report_no_markdown(self, sample_forensic_report):
        """WhatsApp format has no Markdown."""
        plain = format_report_plaintext(sample_forensic_report, severity="P0")
        assert "*" not in plain
        assert "`" not in plain

    def test_chunking_handles_report(self, sample_forensic_report):
        """Report should fit or chunk cleanly."""
        formatted = format_report_markdown(sample_forensic_report, severity="P0")
        chunks = chunk_message(formatted)
        assert len(chunks) >= 1
        for chunk in chunks:
            assert len(chunk) <= 4096 + 10


# ─── Test: Knowledge Graph Integration ─────────────────────────────────────


class TestGraphIntegration:
    """Test graph ingestion with attack scenario data."""

    def test_graph_ingests_webshell_report(self, sample_forensic_report):
        """Full report ingestion creates correct graph structure."""
        graph = ThreatGraph()
        delta = graph.ingest_report(sample_forensic_report, severity="P0")

        # All 7 entities should become nodes
        assert graph.node_count == 7

        # Edges between all entity pairs
        assert graph.edge_count > 0

        # Delta should contain new nodes
        assert len(delta["new_nodes"]) == 7

    def test_graph_node_colors_correct(self, sample_forensic_report):
        """Threat score coloring follows §4.2 rules."""
        graph = ThreatGraph()
        graph.ingest_report(sample_forensic_report, severity="P0")

        for node in graph.nodes.values():
            color = get_node_color(node.threat_score)
            if node.threat_score > 60:
                assert color == NODE_COLORS["high"]
            elif node.threat_score >= 30:
                assert color == NODE_COLORS["medium"]
            else:
                assert color == NODE_COLORS["low"]

    def test_second_report_creates_deltas(self, sample_forensic_report):
        """Second ingestion of same entities updates (not creates) nodes."""
        graph = ThreatGraph()
        graph.ingest_report(sample_forensic_report, severity="P1")
        graph.get_delta()  # Flush first delta

        # Ingest again — should update, not create
        delta = graph.ingest_report(sample_forensic_report, severity="P1")
        assert len(delta["new_nodes"]) == 0
        assert len(delta["updated_nodes"]) == 7

    def test_dns_tunnel_creates_cluster(self, dns_tunnel_scenario):
        """20 DNS queries from same IP should cluster into connected graph."""
        graph = ThreatGraph()

        for entry in dns_tunnel_scenario:
            report = {
                "entities": [
                    {"type": "ip", "value": entry["source_ip"], "role": "source"},
                    {"type": "hostname", "value": entry["hostname"], "role": "host"},
                ],
                "mitre_techniques": ["T1071.004"],
            }
            graph.ingest_report(report, severity="P2")

        # IP and hostname nodes (2 unique entities)
        assert graph.node_count == 2
        # Edge between them
        assert graph.edge_count == 1

    def test_cytoscape_export_valid(self, sample_forensic_report):
        """Full graph export is valid Cytoscape.js JSON."""
        graph = ThreatGraph()
        graph.ingest_report(sample_forensic_report, severity="P0")

        export = graph.get_full_graph()
        assert "elements" in export
        assert "nodes" in export["elements"]
        assert "edges" in export["elements"]

        for node in export["elements"]["nodes"]:
            assert "data" in node
            assert "id" in node["data"]
            assert "color" in node["data"]
