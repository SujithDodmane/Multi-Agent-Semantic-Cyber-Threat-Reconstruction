"""
AEGIS Services — Correlation Compute Backend

FastAPI endpoint that OpenClaw's Correlation SKILL.md calls via HTTP.
Handles embedding via BGE-m3 service, ChromaDB temporal queries, and
cosine similarity thresholding.

Ref: Methodology §3.3 — Correlation SKILL.md Implementation Logic
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

import yaml

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger("aegis.correlation")

app = FastAPI(
    title="AEGIS Correlation API",
    description="Semantic correlation compute backend for OpenClaw Correlation SKILL",
    version="1.0.0",
)

# ─── Configuration ─────────────────────────────────────────────────────────

EMBEDDING_SERVICE_URL = os.getenv("EMBEDDING_SERVICE_URL", "http://localhost:8001")
CHROMADB_HOST = os.getenv("CHROMADB_HOST", "localhost")
CHROMADB_PORT = int(os.getenv("CHROMADB_PORT", "8000"))
SIMILARITY_THRESHOLD = float(os.getenv("SIMILARITY_THRESHOLD", "0.72"))
HNSW_EF_CONSTRUCTION = int(os.getenv("HNSW_EF_CONSTRUCTION", "200"))
HNSW_M = int(os.getenv("HNSW_M", "48"))
DEFAULT_TEMPORAL_WINDOW = 7200  # ±2 hours default
K_NEIGHBORS = 20

# ChromaDB collection names
ACTIVE_COLLECTION = "aegis_active"
COLD_COLLECTION = "aegis_cold"
CHROMADB_PERSIST_DIR = os.getenv("CHROMADB_PERSIST_DIR", "./data/chromadb")

# ─── Per-Event-Type Temporal Windows ────────────────────────────────────────
# Ref: §3.3 — "The time window of ±2 hours is configurable per event_type."

TEMPORAL_WINDOWS: dict[str, int] = {}


def _load_temporal_windows():
    """Load per-event-type temporal windows from intent_templates.yaml."""
    global TEMPORAL_WINDOWS
    try:
        config_path = Path(__file__).parent.parent / "ingestion" / "config" / "intent_templates.yaml"
        if config_path.exists():
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
            TEMPORAL_WINDOWS = config.get("temporal_windows", {})
            logger.info(f"Loaded temporal windows: {len(TEMPORAL_WINDOWS)} entries")
    except Exception as e:
        logger.warning(f"Failed to load temporal windows: {e}")


def get_temporal_window(event_type: str) -> int:
    """Get the temporal window (seconds) for a given event type."""
    return TEMPORAL_WINDOWS.get(event_type, TEMPORAL_WINDOWS.get("default", DEFAULT_TEMPORAL_WINDOW))


# Load on module import
_load_temporal_windows()


# ─── Request/Response Models ───────────────────────────────────────────────


class CorrelateRequest(BaseModel):
    """Request body for POST /correlate."""
    synthetic_intent: str
    event_timestamp: float = Field(description="Unix timestamp of the triggering event")
    log_uuid: str
    event_type: str = ""


class CorrelatedEntry(BaseModel):
    """A single correlated result."""
    log_uuid: str
    synthetic_intent: str
    cosine_similarity: float
    event_timestamp: str
    event_type: str = ""
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    hostname: str = ""


class CorrelateResponse(BaseModel):
    """Response from POST /correlate."""
    correlated_entries: list[CorrelatedEntry] = Field(default_factory=list)
    cluster_size: int = 0
    temporal_span_minutes: float = 0.0
    cold_start: bool = False
    error: Optional[str] = None


# ─── Embedding Call ────────────────────────────────────────────────────────


async def _get_embedding(text: str) -> Optional[list[float]]:
    """
    Call the BGE-m3 embedding service.

    Ref: Methodology §3.1 — "POST /embed accepts a synthetic_intent string
    and returns a 384-dimensional float array"
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{EMBEDDING_SERVICE_URL}/embed",
                json={"text": text},
            )
            response.raise_for_status()
            return response.json().get("embedding")
    except Exception as e:
        logger.error(f"Embedding service call failed: {e}")
        return None


# ─── ChromaDB Query ────────────────────────────────────────────────────────


async def _query_chromadb(
    embedding: list[float],
    event_timestamp: float,
    exclude_uuid: str,
    temporal_window: int = DEFAULT_TEMPORAL_WINDOW,
) -> list[dict]:
    """
    Query ChromaDB with temporal pre-filter.

    Ref: Methodology §3.3:
    - "event_timestamp must be between (target - 7200) and (target + 7200)"
    - "This filter is applied before the HNSW nearest-neighbor search, not after"
    - "ChromaDB evaluates metadata filters as pre-filters"

    Ref: Methodology §3.2:
    - "HNSW index parameters: ef_construction=200, M=48"
    """
    window_seconds = temporal_window
    ts_min = event_timestamp - window_seconds
    ts_max = event_timestamp + window_seconds

    try:
        # Use ChromaDB Persistent client
        import chromadb
        client = chromadb.PersistentClient(path=CHROMADB_PERSIST_DIR)

        # Get or create collection with correct HNSW params
        collection = client.get_or_create_collection(
            name=ACTIVE_COLLECTION,
            metadata={
                "hnsw:construction_ef": HNSW_EF_CONSTRUCTION,
                "hnsw:M": HNSW_M,
            },
        )

        if collection.count() == 0:
            logger.info("ChromaDB collection is empty — cold start")
            return []

        # Temporal pre-filter query
        results = collection.query(
            query_embeddings=[embedding],
            n_results=min(K_NEIGHBORS, collection.count()),
            where={
                "$and": [
                    {"event_timestamp": {"$gte": ts_min}},
                    {"event_timestamp": {"$lte": ts_max}},
                ]
            },
            include=["documents", "metadatas", "distances"],
        )

        # Process results
        entries = []
        if results and results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                metadata = results["metadatas"][0][i] if results["metadatas"] else {}
                distance = results["distances"][0][i] if results["distances"] else 1.0

                # Skip self-match
                if metadata.get("log_uuid") == exclude_uuid:
                    continue

                # Convert distance to similarity
                # Ref: §3.3 — "similarity = 1 - distance"
                similarity = 1 - distance

                # Apply threshold
                # Ref: §3.3 — "minimum similarity threshold of 0.72"
                if similarity < SIMILARITY_THRESHOLD:
                    continue

                entries.append({
                    "log_uuid": metadata.get("log_uuid", doc_id),
                    "synthetic_intent": results["documents"][0][i] if results["documents"] else "",
                    "cosine_similarity": round(similarity, 4),
                    "event_timestamp": str(metadata.get("event_timestamp", "")),
                    "event_type": metadata.get("event_type", ""),
                    "source_ip": metadata.get("source_ip"),
                    "dest_ip": metadata.get("dest_ip"),
                    "hostname": metadata.get("hostname", ""),
                })

        return entries

    except Exception as e:
        logger.error(f"ChromaDB query failed: {e}")
        return []


# ─── Endpoint ──────────────────────────────────────────────────────────────


# --- Storage Logic ---


async def _store_in_chromadb(embedding: list[float], synthetic_intent: str, log_uuid: str, event_timestamp: float, event_type: str, source_ip: str = None, dest_ip: str = None, hostname: str = ""):
    """
    Store an embedding and its metadata in ChromaDB.
    
    Ref: Methodology §3.1 — "Every ingested log... must be embedded and stored in the ChromaDB vector space"
    """
    try:
        import chromadb
        client = chromadb.PersistentClient(path=CHROMADB_PERSIST_DIR)
        collection = client.get_or_create_collection(
            name=ACTIVE_COLLECTION,
            metadata={
                "hnsw:construction_ef": 200,
                "hnsw:M": HNSW_M,
            },
        )
        
        collection.add(
            ids=[log_uuid],
            embeddings=[embedding],
            documents=[synthetic_intent],
            metadatas=[{
                "log_uuid": log_uuid,
                "event_timestamp": event_timestamp,
                "event_type": event_type,
                "source_ip": source_ip or "unknown",
                "dest_ip": dest_ip or "unknown",
                "hostname": hostname or "unknown"
            }]
        )
        logger.info(f"Stored log {log_uuid} in ChromaDB")
        return True
    except Exception as e:
        logger.error(f"Failed to store in ChromaDB: {e}")
        return False


# ─── Endpoints ─────────────────────────────────────────────────────────────


class IngestRequest(BaseModel):
    """Request body for POST /ingest."""
    synthetic_intent: str
    log_uuid: str
    event_timestamp: float
    event_type: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    hostname: str = ""


@app.post("/ingest")
async def ingest(request: IngestRequest):
    """
    Ingest a log into the semantic vector store.
    
    Called by OpenClaw's Storage SKILL/logic for every log.
    """
    embedding = await _get_embedding(request.synthetic_intent)
    if embedding is None:
        raise HTTPException(status_code=503, detail="Embedding service unavailable")
    
    success = await _store_in_chromadb(
        embedding=embedding,
        synthetic_intent=request.synthetic_intent,
        log_uuid=request.log_uuid,
        event_timestamp=request.event_timestamp,
        event_type=request.event_type,
        source_ip=request.source_ip,
        dest_ip=request.dest_ip,
        hostname=request.hostname
    )
    
    return {"success": success, "log_uuid": request.log_uuid}


@app.post("/correlate", response_model=CorrelateResponse)
async def correlate(request: CorrelateRequest):
    """
    Find semantically correlated events for a triggering log entry.

    Called by OpenClaw's Correlation SKILL.md via HTTP.

    Flow:
    1. Get embedding vector from BGE-m3 service
    2. Query ChromaDB with temporal pre-filter (±2hr)
    3. Apply cosine similarity threshold (≥0.72)
    4. Return correlated cluster

    Ref: Methodology §3.3 — Complete correlation logic
    """
    # 1. Get embedding
    embedding = await _get_embedding(request.synthetic_intent)
    if embedding is None:
        return CorrelateResponse(
            cold_start=True,
            error="Embedding service unavailable",
        )

    # 2. Query ChromaDB
    # Get per-event-type temporal window
    temporal_window = get_temporal_window(request.event_type)

    entries = await _query_chromadb(
        embedding=embedding,
        event_timestamp=request.event_timestamp,
        exclude_uuid=request.log_uuid,
        temporal_window=temporal_window,
    )

    # 3. Check for cold start
    if not entries:
        return CorrelateResponse(
            cold_start=True,
            cluster_size=0,
        )

    # 4. Build response
    correlated = [CorrelatedEntry(**e) for e in entries]

    # Calculate temporal span
    timestamps = []
    for e in entries:
        try:
            ts = float(e.get("event_timestamp", 0))
            if ts > 0:
                timestamps.append(ts)
        except (ValueError, TypeError):
            pass

    temporal_span = 0.0
    if len(timestamps) >= 2:
        temporal_span = (max(timestamps) - min(timestamps)) / 60.0  # minutes

    return CorrelateResponse(
        correlated_entries=correlated,
        cluster_size=len(correlated),
        temporal_span_minutes=round(temporal_span, 2),
        cold_start=False,
    )


@app.get("/health")
async def health():
    """Check correlation service dependencies."""
    embedding_ok = False
    chromadb_ok = False

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{EMBEDDING_SERVICE_URL}/health")
            embedding_ok = resp.status_code == 200
    except Exception:
        pass

    try:
        import chromadb
        client = chromadb.PersistentClient(path=CHROMADB_PERSIST_DIR)
        client.heartbeat()
        chromadb_ok = True
    except Exception:
        pass

    return {
        "status": "healthy" if (embedding_ok and chromadb_ok) else "degraded",
        "embedding_service": embedding_ok,
        "chromadb": chromadb_ok,
    }
