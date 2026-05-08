"""
AEGIS — Knowledge Graph WebSocket + HTTP Service

Maintains the real-time threat investigation graph. Receives forensic
reports via HTTP and pushes graph deltas to connected Cytoscape.js
browser clients via WebSocket.

Ports:
  - HTTP: 5000 (serves static UI + REST API)
  - WebSocket: 5001 (delta push to browsers)

Ref: Methodology §4.2 — Knowledge Graph Construction
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from services.graph.graph_model import ThreatGraph

logger = logging.getLogger("aegis.graph")

app = FastAPI(
    title="AEGIS Knowledge Graph Service",
    description="Real-time threat knowledge graph with WebSocket delta push",
    version="1.0.0",
)

# ─── Global State ──────────────────────────────────────────────────────────

graph = ThreatGraph()
connected_clients: list[WebSocket] = []

# ─── Static Files ─────────────────────────────────────────────────────────

STATIC_DIR = Path(__file__).parent / "static"


@app.on_event("startup")
async def startup():
    """Mount static files if directory exists."""
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
        logger.info(f"Static files served from {STATIC_DIR}")


@app.get("/")
async def index():
    """Serve the Cytoscape.js graph viewer."""
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"message": "AEGIS Knowledge Graph — UI not found", "api": "/docs"}


# ─── Request/Response Models ───────────────────────────────────────────────


class ReportIngestionRequest(BaseModel):
    """Request body for POST /graph/ingest."""
    report: dict = Field(description="ForensicReport as dict")
    severity: str = Field(default="P1")


# ─── WebSocket Endpoint ───────────────────────────────────────────────────


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """
    WebSocket connection for Cytoscape.js browser clients.

    Ref: §4.2 — "The WebSocket server maintains a list of connected
    browser clients. When a new report arrives, it broadcasts an update
    message containing only the delta."
    """
    await ws.accept()
    connected_clients.append(ws)
    logger.info(f"WebSocket client connected ({len(connected_clients)} total)")

    try:
        # Send full graph on connect
        full = graph.get_full_graph()
        await ws.send_json({"type": "full", **full})

        # Keep alive — listen for pings
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_json({"type": "pong"})
    except WebSocketDisconnect:
        connected_clients.remove(ws)
        logger.info(f"WebSocket client disconnected ({len(connected_clients)} total)")
    except Exception as e:
        if ws in connected_clients:
            connected_clients.remove(ws)
        logger.error(f"WebSocket error: {e}")


async def broadcast_delta(delta: dict):
    """
    Broadcast a graph delta to all connected WebSocket clients.

    Ref: §4.2 — "broadcasts an update message containing only the delta —
    new nodes and new edges, not the entire graph"
    """
    if not connected_clients:
        return

    message = json.dumps(delta)
    disconnected = []

    for client in connected_clients:
        try:
            await client.send_text(message)
        except Exception:
            disconnected.append(client)

    # Cleanup disconnected clients
    for client in disconnected:
        if client in connected_clients:
            connected_clients.remove(client)


# ─── HTTP Endpoints ───────────────────────────────────────────────────────


@app.post("/graph/ingest")
async def ingest_report(request: ReportIngestionRequest):
    """
    Ingest a ForensicReport and update the knowledge graph.

    Extracts entities and edges, updates threat scores,
    and broadcasts delta to WebSocket clients.
    """
    delta = graph.ingest_report(request.report, severity=request.severity)

    # Broadcast to connected browsers
    await broadcast_delta(delta)

    return {
        "ingested": True,
        "new_nodes": len(delta.get("new_nodes", [])),
        "updated_nodes": len(delta.get("updated_nodes", [])),
        "new_edges": len(delta.get("new_edges", [])),
        "total_nodes": graph.node_count,
        "total_edges": graph.edge_count,
    }


@app.get("/graph/full")
async def get_full_graph():
    """Get the complete graph in Cytoscape.js format."""
    return graph.get_full_graph()


@app.get("/graph/stats")
async def graph_stats():
    """Get graph statistics."""
    return {
        "total_nodes": graph.node_count,
        "total_edges": graph.edge_count,
        "connected_clients": len(connected_clients),
    }


@app.get("/health")
async def health():
    """Health check for the graph service."""
    return {
        "status": "healthy",
        "graph_nodes": graph.node_count,
        "graph_edges": graph.edge_count,
        "websocket_clients": len(connected_clients),
    }
