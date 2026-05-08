"""
AEGIS — Knowledge Graph Data Model

In-memory graph data structure for the real-time threat investigation graph.
Nodes represent entities (IPs, hostnames, processes, users, files).
Edges represent observed interactions.

Features:
  - Node upsert with threat_score accumulation
  - Edge creation from ForensicReport entities + correlations
  - Delta computation for WebSocket push (new nodes/edges only)
  - Cytoscape.js JSON export format
  - Color assignment by threat_score

Ref: Methodology §4.2 — Knowledge Graph Construction
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Optional


# ─── Node Color Strategy ──────────────────────────────────────────────────
# Ref: §4.2 — "nodes with threat_score below 30 are blue (low risk),
# 30–60 are amber (medium risk), above 60 are red (high risk)"

NODE_COLORS = {
    "low": "#3498db",     # Blue — threat_score < 30
    "medium": "#f39c12",  # Amber — 30 ≤ threat_score ≤ 60
    "high": "#e74c3c",    # Red — threat_score > 60
}

NODE_TYPE_SHAPES = {
    "ip": "ellipse",
    "hostname": "round-rectangle",
    "process": "diamond",
    "user": "triangle",
    "file": "rectangle",
}


def get_node_color(threat_score: float) -> str:
    """Get node color based on threat score."""
    if threat_score > 60:
        return NODE_COLORS["high"]
    elif threat_score >= 30:
        return NODE_COLORS["medium"]
    else:
        return NODE_COLORS["low"]


def get_risk_level(threat_score: float) -> str:
    """Get risk level label."""
    if threat_score > 60:
        return "high"
    elif threat_score >= 30:
        return "medium"
    else:
        return "low"


# ─── Graph Data Model ─────────────────────────────────────────────────────


class GraphNode:
    """
    A node in the knowledge graph.

    Ref: §4.2 — "nodes represent entities (IPs, hostnames, processes,
    user accounts, file paths). Each node has a type attribute, a label,
    a threat_score, and first_seen/last_seen timestamps."
    """

    def __init__(self, node_id: str, node_type: str, label: str,
                 threat_score: float = 0.0):
        self.id = node_id
        self.type = node_type  # ip, hostname, process, user, file
        self.label = label
        self.threat_score = threat_score
        self.first_seen = datetime.now(timezone.utc).isoformat()
        self.last_seen = self.first_seen

    def update(self, score_delta: float = 0.0):
        """Update node with new observation."""
        self.threat_score = min(100.0, self.threat_score + score_delta)
        self.last_seen = datetime.now(timezone.utc).isoformat()

    def to_cytoscape(self) -> dict:
        """Export as Cytoscape.js node data."""
        return {
            "data": {
                "id": self.id,
                "label": self.label,
                "type": self.type,
                "threat_score": round(self.threat_score, 1),
                "risk_level": get_risk_level(self.threat_score),
                "color": get_node_color(self.threat_score),
                "shape": NODE_TYPE_SHAPES.get(self.type, "ellipse"),
                "first_seen": self.first_seen,
                "last_seen": self.last_seen,
            }
        }


class GraphEdge:
    """
    An edge in the knowledge graph.

    Ref: §4.2 — "edges represent observed interactions. Each edge has a
    type attribute, a timestamp, a cosine_similarity_score, and a
    mitre_technique_id if applicable."
    """

    def __init__(self, source_id: str, target_id: str,
                 edge_type: str = "interaction",
                 cosine_similarity: float = 0.0,
                 mitre_technique_id: str = ""):
        self.id = f"e_{source_id}_{target_id}_{edge_type}"
        self.source = source_id
        self.target = target_id
        self.type = edge_type  # network_connection, process_spawn, file_write, authentication
        self.cosine_similarity = cosine_similarity
        self.mitre_technique_id = mitre_technique_id
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_cytoscape(self) -> dict:
        """Export as Cytoscape.js edge data."""
        label = self.mitre_technique_id if self.mitre_technique_id else self.type
        return {
            "data": {
                "id": self.id,
                "source": self.source,
                "target": self.target,
                "type": self.type,
                "label": label,
                "cosine_similarity": round(self.cosine_similarity, 3),
                "mitre_technique_id": self.mitre_technique_id,
                "timestamp": self.timestamp,
            }
        }


class ThreatGraph:
    """
    In-memory knowledge graph with delta tracking.

    Ref: §4.2 — "The WebSocket server broadcasts an update message
    containing only the delta — new nodes and new edges, not the entire graph."
    """

    def __init__(self):
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[str, GraphEdge] = {}
        # Track new additions since last delta flush
        self._new_node_ids: set[str] = set()
        self._new_edge_ids: set[str] = set()
        self._updated_node_ids: set[str] = set()

    def _make_node_id(self, node_type: str, value: str) -> str:
        """Create a deterministic node ID."""
        return f"{node_type}:{value}".replace(" ", "_").lower()

    def add_node(self, node_type: str, label: str,
                 score_delta: float = 10.0) -> GraphNode:
        """
        Add or update a node.

        Ref: §4.2 — "threat_score (updated with each new report
        mentioning this entity)"
        """
        node_id = self._make_node_id(node_type, label)

        if node_id in self.nodes:
            self.nodes[node_id].update(score_delta)
            self._updated_node_ids.add(node_id)
        else:
            node = GraphNode(node_id, node_type, label, threat_score=score_delta)
            self.nodes[node_id] = node
            self._new_node_ids.add(node_id)

        return self.nodes[node_id]

    def add_edge(self, source_type: str, source_label: str,
                 target_type: str, target_label: str,
                 edge_type: str = "interaction",
                 cosine_similarity: float = 0.0,
                 mitre_technique_id: str = "") -> GraphEdge:
        """Add an edge between two nodes (creates nodes if needed)."""
        # Ensure nodes exist
        self.add_node(source_type, source_label, score_delta=0)
        self.add_node(target_type, target_label, score_delta=0)

        source_id = self._make_node_id(source_type, source_label)
        target_id = self._make_node_id(target_type, target_label)

        edge = GraphEdge(
            source_id, target_id, edge_type,
            cosine_similarity, mitre_technique_id,
        )

        if edge.id not in self.edges:
            self.edges[edge.id] = edge
            self._new_edge_ids.add(edge.id)

        return edge

    def ingest_report(self, report: dict, severity: str = "P1") -> dict:
        """
        Ingest a ForensicReport and extract graph entities/edges.
        """
        score_map = {"P0": 30.0, "P1": 20.0, "P2": 10.0}
        base_score = score_map.get(severity, 10.0)

        entities = report.get("entities", [])
        techniques = report.get("mitre_techniques", [])
        primary_technique = techniques[0] if techniques else ""

        entity_nodes = []
        for entity in entities:
            etype = entity.get("type", "unknown")
            value = entity.get("value", "")
            if value:
                self.add_node(etype, value, score_delta=base_score)
                entity_nodes.append((etype, value))

        for i, (t1, v1) in enumerate(entity_nodes):
            for t2, v2 in entity_nodes[i + 1:]:
                self.add_edge(
                    t1, v1, t2, v2,
                    edge_type=_infer_edge_type(t1, t2),
                    mitre_technique_id=primary_technique,
                )
        return self.get_delta()

    def ingest_raw_log(self, entry: dict) -> dict:
        """
        Extract entities from a raw normalized log entry and update the graph.
        """
        hostname = entry.get("hostname")
        source_ip = entry.get("source_ip")
        dest_ip = entry.get("dest_ip")
        process_name = entry.get("process_name")
        user_account = entry.get("user_account")
        
        entities = []
        if hostname and hostname != "unknown_host":
            entities.append(("hostname", hostname))
        if source_ip and source_ip != "unknown":
            entities.append(("ip", source_ip))
        if dest_ip and dest_ip != "unknown":
            entities.append(("ip", dest_ip))
        if process_name and process_name != "unknown":
            entities.append(("process", process_name))
        if user_account and user_account != "unknown":
            entities.append(("user", user_account))

        for etype, evalue in entities:
            self.add_node(etype, evalue, score_delta=5.0)

        if hostname and source_ip:
            self.add_edge("hostname", hostname, "ip", source_ip, edge_type="has_interface")
        if process_name and hostname:
            self.add_edge("process", process_name, "hostname", hostname, edge_type="executed_on")
        if user_account and process_name:
            self.add_edge("user", user_account, "process", process_name, edge_type="launched")
        if source_ip and dest_ip:
            self.add_edge("ip", source_ip, "ip", dest_ip, edge_type="network_connection")

        return self.get_delta()

    def get_delta(self) -> dict:
        """
        Get graph changes since last flush.

        Ref: §4.2 — "broadcasts only the delta — new nodes and new edges"
        """
        new_nodes = [self.nodes[nid].to_cytoscape() for nid in self._new_node_ids if nid in self.nodes]
        updated_nodes = [self.nodes[nid].to_cytoscape() for nid in self._updated_node_ids if nid in self.nodes]
        new_edges = [self.edges[eid].to_cytoscape() for eid in self._new_edge_ids if eid in self.edges]

        delta = {
            "type": "delta",
            "new_nodes": new_nodes,
            "updated_nodes": updated_nodes,
            "new_edges": new_edges,
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
        }

        # Flush tracking
        self._new_node_ids.clear()
        self._new_edge_ids.clear()
        self._updated_node_ids.clear()

        return delta

    def get_full_graph(self) -> dict:
        """Export the complete graph in Cytoscape.js format."""
        return {
            "elements": {
                "nodes": [n.to_cytoscape() for n in self.nodes.values()],
                "edges": [e.to_cytoscape() for e in self.edges.values()],
            },
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
        }

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)


def _infer_edge_type(type1: str, type2: str) -> str:
    """Infer edge type from the two connected node types."""
    pair = frozenset([type1, type2])
    if pair == frozenset(["ip", "ip"]):
        return "network_connection"
    elif "process" in pair:
        return "process_spawn"
    elif "file" in pair:
        return "file_write"
    elif "user" in pair:
        return "authentication"
    else:
        return "interaction"
