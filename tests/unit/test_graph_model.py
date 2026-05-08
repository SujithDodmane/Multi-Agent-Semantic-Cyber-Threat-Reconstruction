"""
AEGIS Unit Tests — Knowledge Graph Model

Tests node creation, edge creation, threat score coloring,
delta computation, Cytoscape.js export, and report ingestion.

Ref: Methodology §4.2 — Knowledge Graph Construction
Ref: TABLE 13 — "Node threat_score coloring: blue (<30), amber (30–60), red (>60)"
"""

import pytest

from services.graph.graph_model import (
    ThreatGraph,
    GraphNode,
    GraphEdge,
    get_node_color,
    get_risk_level,
    NODE_COLORS,
    _infer_edge_type,
)


# ─── Node Color Tests ─────────────────────────────────────────────────────


class TestNodeColoring:
    """
    Ref: §4.2 — "nodes with threat_score below 30 are blue (low risk),
    30–60 are amber (medium risk), above 60 are red (high risk)"
    """

    def test_low_risk_blue(self):
        assert get_node_color(0) == NODE_COLORS["low"]
        assert get_node_color(29) == NODE_COLORS["low"]

    def test_medium_risk_amber(self):
        assert get_node_color(30) == NODE_COLORS["medium"]
        assert get_node_color(45) == NODE_COLORS["medium"]
        assert get_node_color(60) == NODE_COLORS["medium"]

    def test_high_risk_red(self):
        assert get_node_color(61) == NODE_COLORS["high"]
        assert get_node_color(100) == NODE_COLORS["high"]

    def test_risk_level_labels(self):
        assert get_risk_level(10) == "low"
        assert get_risk_level(40) == "medium"
        assert get_risk_level(80) == "high"


# ─── Graph Node Tests ─────────────────────────────────────────────────────


class TestGraphNode:
    """Test node creation and updates."""

    def test_node_creation(self):
        node = GraphNode("ip:10.0.0.1", "ip", "10.0.0.1", threat_score=25.0)
        assert node.id == "ip:10.0.0.1"
        assert node.type == "ip"
        assert node.label == "10.0.0.1"
        assert node.threat_score == 25.0
        assert node.first_seen is not None

    def test_node_update_score(self):
        node = GraphNode("ip:10.0.0.1", "ip", "10.0.0.1", threat_score=20.0)
        original_score = node.threat_score
        node.update(score_delta=15.0)
        assert node.threat_score == 35.0
        assert node.threat_score > original_score
        # last_seen is updated (it exists and is a valid timestamp)
        assert node.last_seen is not None

    def test_node_score_cap(self):
        """Threat score should not exceed 100."""
        node = GraphNode("ip:10.0.0.1", "ip", "10.0.0.1", threat_score=90.0)
        node.update(score_delta=20.0)
        assert node.threat_score == 100.0

    def test_cytoscape_export(self):
        node = GraphNode("ip:10.0.0.1", "ip", "10.0.0.1", threat_score=25.0)
        cy = node.to_cytoscape()
        assert "data" in cy
        assert cy["data"]["id"] == "ip:10.0.0.1"
        assert cy["data"]["label"] == "10.0.0.1"
        assert cy["data"]["color"] == NODE_COLORS["low"]
        assert cy["data"]["shape"] == "ellipse"


# ─── Graph Edge Tests ──────────────────────────────────────────────────────


class TestGraphEdge:
    """Test edge creation and export."""

    def test_edge_creation(self):
        edge = GraphEdge(
            "ip:10.0.0.1", "ip:10.0.0.2",
            edge_type="network_connection",
            cosine_similarity=0.85,
            mitre_technique_id="T1021",
        )
        assert edge.source == "ip:10.0.0.1"
        assert edge.target == "ip:10.0.0.2"
        assert edge.type == "network_connection"
        assert edge.cosine_similarity == 0.85
        assert edge.mitre_technique_id == "T1021"

    def test_cytoscape_export(self):
        edge = GraphEdge(
            "ip:10.0.0.1", "ip:10.0.0.2",
            mitre_technique_id="T1021",
        )
        cy = edge.to_cytoscape()
        assert "data" in cy
        assert cy["data"]["source"] == "ip:10.0.0.1"
        assert cy["data"]["target"] == "ip:10.0.0.2"
        assert cy["data"]["label"] == "T1021"


# ─── Edge Type Inference Tests ─────────────────────────────────────────────


class TestEdgeTypeInference:
    """Test automatic edge type inference."""

    def test_ip_to_ip_is_network(self):
        assert _infer_edge_type("ip", "ip") == "network_connection"

    def test_process_related_is_spawn(self):
        assert _infer_edge_type("process", "hostname") == "process_spawn"

    def test_file_related_is_write(self):
        assert _infer_edge_type("hostname", "file") == "file_write"

    def test_user_related_is_auth(self):
        assert _infer_edge_type("user", "hostname") == "authentication"


# ─── Threat Graph Tests ───────────────────────────────────────────────────


class TestThreatGraph:
    """Test the full graph with delta tracking."""

    def test_add_node(self):
        g = ThreatGraph()
        node = g.add_node("ip", "10.0.0.1", score_delta=10.0)
        assert g.node_count == 1
        assert node.threat_score == 10.0

    def test_node_upsert(self):
        """
        Ref: §4.2 — "threat_score (updated with each new report
        mentioning this entity)"
        """
        g = ThreatGraph()
        g.add_node("ip", "10.0.0.1", score_delta=10.0)
        g.add_node("ip", "10.0.0.1", score_delta=15.0)
        assert g.node_count == 1  # Same node
        node = g.nodes[g._make_node_id("ip", "10.0.0.1")]
        assert node.threat_score == 25.0

    def test_add_edge(self):
        g = ThreatGraph()
        edge = g.add_edge("ip", "10.0.0.1", "ip", "10.0.0.2", edge_type="network_connection")
        assert g.edge_count == 1
        assert g.node_count == 2  # Both nodes created

    def test_delta_tracking(self):
        """
        Ref: §4.2 — "broadcasts only the delta — new nodes and new edges"
        """
        g = ThreatGraph()
        g.add_node("ip", "10.0.0.1", score_delta=10.0)
        g.add_node("ip", "10.0.0.2", score_delta=20.0)

        delta = g.get_delta()
        assert len(delta["new_nodes"]) == 2
        assert len(delta["new_edges"]) == 0
        assert delta["type"] == "delta"

        # After flush, delta should be empty
        delta2 = g.get_delta()
        assert len(delta2["new_nodes"]) == 0

    def test_delta_updated_nodes(self):
        g = ThreatGraph()
        g.add_node("ip", "10.0.0.1", score_delta=10.0)
        g.get_delta()  # Flush

        g.add_node("ip", "10.0.0.1", score_delta=5.0)  # Update
        delta = g.get_delta()
        assert len(delta["updated_nodes"]) == 1
        assert len(delta["new_nodes"]) == 0

    def test_full_graph_export(self):
        g = ThreatGraph()
        g.add_node("ip", "10.0.0.1")
        g.add_edge("ip", "10.0.0.1", "hostname", "WEBSERVER01")

        full = g.get_full_graph()
        assert "elements" in full
        assert len(full["elements"]["nodes"]) == 2
        assert len(full["elements"]["edges"]) == 1

    def test_ingest_report(self):
        """Test full report ingestion pipeline."""
        g = ThreatGraph()
        report = {
            "entities": [
                {"type": "ip", "value": "10.0.0.1", "role": "source"},
                {"type": "process", "value": "mimikatz.exe", "role": "tool"},
                {"type": "hostname", "value": "DC01", "role": "target"},
            ],
            "mitre_techniques": ["T1003"],
        }

        delta = g.ingest_report(report, severity="P0")
        assert g.node_count == 3
        assert g.edge_count == 3  # 3 pairs: ip-process, ip-hostname, process-hostname
        assert len(delta["new_nodes"]) == 3

    def test_deterministic_node_ids(self):
        g = ThreatGraph()
        id1 = g._make_node_id("ip", "10.0.0.1")
        id2 = g._make_node_id("ip", "10.0.0.1")
        assert id1 == id2  # Same input → same ID
