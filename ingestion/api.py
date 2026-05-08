"""
AEGIS Ingestion — FastAPI Queue API

Exposes the asyncio.PriorityQueue to the OpenClaw orchestrator via HTTP.
This is the bridge between Plane 1 (Python ingestion) and Plane 2 (OpenClaw Node.js).

Endpoints:
  GET  /queue/next    — Dequeue highest-priority item (200ms timeout)
  GET  /queue/stats   — Queue depth, enqueued count, dropped count
  GET  /health        — Daemon health check
  POST /queue/inject  — Manual log injection for testing/demo

Ref: Methodology §2.1 — "it polls the asyncio.PriorityQueue endpoint (exposed
as a FastAPI GET endpoint by the Python ingestion service)"
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ingestion.db import DatabaseManager
from ingestion.intent_translator import translate_entry
from ingestion.models import EventType, NormalizedLogEntry, Severity
from ingestion.priority_queue import AegisPriorityQueue, compute_severity

logger = logging.getLogger("aegis.api")

# ─── FastAPI Application ───────────────────────────────────────────────────

app = FastAPI(
    title="AEGIS Ingestion API",
    description="Plane 1 queue interface for OpenClaw orchestrator polling",
    version="1.0.0",
)

# Shared state — initialized by the daemon at startup
_queue: Optional[AegisPriorityQueue] = None
_db: Optional[DatabaseManager] = None


def init_api(queue: AegisPriorityQueue, db: DatabaseManager) -> None:
    """Initialize the API with shared daemon state."""
    global _queue, _db
    _queue = queue
    _db = db


# ─── Response Models ───────────────────────────────────────────────────────


class QueueItemResponse(BaseModel):
    """Response from GET /queue/next — a dequeued log entry."""
    found: bool
    priority: Optional[int] = None
    severity: Optional[str] = None
    entry: Optional[dict] = None


class QueueStatsResponse(BaseModel):
    """Response from GET /queue/stats."""
    depth: int
    total_enqueued: int
    total_dropped: int
    max_depth: int


class InjectRequest(BaseModel):
    """Request body for POST /queue/inject — manual log injection."""
    raw_line: str
    event_type: str = "UNKNOWN"
    hostname: str = "TEST-HOST"
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    process_name: Optional[str] = None
    parent_process_name: Optional[str] = None
    user_account: Optional[str] = None
    dns_query: Optional[str] = None
    file_path: Optional[str] = None
    http_url: Optional[str] = None
    http_method: Optional[str] = None
    command_line_args: Optional[str] = None


class InjectResponse(BaseModel):
    """Response from POST /queue/inject."""
    log_uuid: str
    severity: str
    synthetic_intent: str
    queued: bool


# ─── Endpoints ─────────────────────────────────────────────────────────────


@app.get("/queue/next", response_model=QueueItemResponse)
async def queue_next():
    """
    Dequeue the highest-priority item from the queue.

    Non-blocking with 200ms timeout — if no item is available,
    returns {found: false} immediately.

    Ref: Methodology §2.1 — "Implement the poll with a timeout of 200ms —
    if no response arrives, the heartbeat skips this tick"
    """
    if _queue is None:
        raise HTTPException(status_code=503, detail="Queue not initialized")

    item = await _queue.dequeue_wait(timeout=0.2)

    if item is None:
        return QueueItemResponse(found=False)

    return QueueItemResponse(
        found=True,
        priority=item.priority,
        severity=item.severity.value,
        entry=item.entry.model_dump(),
    )


@app.get("/queue/stats", response_model=QueueStatsResponse)
async def queue_stats():
    """Get current queue statistics for monitoring."""
    if _queue is None:
        raise HTTPException(status_code=503, detail="Queue not initialized")

    stats = _queue.get_stats()
    return QueueStatsResponse(**stats)


@app.get("/health")
async def health():
    """Daemon health check."""
    return {
        "status": "healthy",
        "service": "aegis-ingestion",
        "queue_initialized": _queue is not None,
        "db_initialized": _db is not None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/queue/inject", response_model=InjectResponse)
async def queue_inject(request: InjectRequest):
    """
    Manually inject a log entry into the pipeline.
    Used for testing and demo attack scenario injection.
    """
    if _queue is None or _db is None:
        raise HTTPException(status_code=503, detail="Service not initialized")

    # Build a NormalizedLogEntry from the inject request
    try:
        event_type = EventType(request.event_type)
    except ValueError:
        event_type = EventType.UNKNOWN

    entry = NormalizedLogEntry(
        log_uuid=str(uuid.uuid4()),
        ingestion_timestamp=datetime.now(timezone.utc).isoformat(),
        event_timestamp=datetime.now(timezone.utc).isoformat(),
        event_type=event_type,
        hostname=request.hostname,
        sha256_hash=hashlib.sha256(request.raw_line.encode()).hexdigest(),
        raw_payload=request.raw_line,
        source_ip=request.source_ip,
        dest_ip=request.dest_ip,
        dest_port=request.dest_port,
        process_name=request.process_name,
        parent_process_name=request.parent_process_name,
        user_account=request.user_account,
        dns_query=request.dns_query,
        file_path=request.file_path,
        http_url=request.http_url,
        http_method=request.http_method,
        command_line_args=request.command_line_args,
    )

    # Run through intent translation
    entry = translate_entry(entry)

    # Store in SQLite
    _db.store_log_entry(entry)

    # Enqueue
    severity = await _queue.enqueue(entry)
    queued = severity is not None and severity != Severity.BENIGN

    return InjectResponse(
        log_uuid=entry.log_uuid,
        severity=(severity.value if severity else "BENIGN"),
        synthetic_intent=entry.synthetic_intent,
        queued=queued,
    )
