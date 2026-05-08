"""
AEGIS — ChromaDB Ingestion Pipeline

Bridges Plane 1 (SQLite log store) → Plane 3 (vector store).
Every normalized log entry is embedded and stored in ChromaDB
for semantic correlation queries.

Document structure per §3.2:
  - document: synthetic_intent string (retrievable for forensic reports)
  - embedding: 384-dim float vector from BGE-m3
  - metadata: log_uuid, event_timestamp, event_type, source_ip,
              dest_ip, hostname, severity

Ref: Methodology §3.2 — ChromaDB Collection Design
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

import httpx

logger = logging.getLogger("aegis.chromadb_ingester")

# ─── Configuration ─────────────────────────────────────────────────────────

EMBEDDING_SERVICE_URL = os.getenv("EMBEDDING_SERVICE_URL", "http://localhost:8001")
CHROMADB_HOST = os.getenv("CHROMADB_HOST", "localhost")
CHROMADB_PORT = int(os.getenv("CHROMADB_PORT", "8000"))

ACTIVE_COLLECTION = "logs_active"
ARCHIVE_COLLECTION = "logs_archive"


def _get_chromadb_client():
    """Get ChromaDB HTTP client."""
    import chromadb
    return chromadb.HttpClient(host=CHROMADB_HOST, port=CHROMADB_PORT)


def _ensure_collection(client, name: str):
    """
    Get or create a ChromaDB collection with correct HNSW parameters.

    Ref: §3.2 — "ef_construction=200, M=48. These values produce an index
    that balances search speed and recall — higher values give better recall
    but slower build and query times."
    """
    return client.get_or_create_collection(
        name=name,
        metadata={
            "hnsw:construction_ef": 200,
            "hnsw:M": 48,
        },
    )


# ─── Single Entry Ingestion ───────────────────────────────────────────────


async def ingest_entry(
    entry_dict: dict,
    embedding: Optional[list[float]] = None,
) -> bool:
    """
    Ingest a single NormalizedLogEntry into ChromaDB.

    Args:
        entry_dict: Dictionary representation of NormalizedLogEntry
        embedding: Pre-computed embedding vector. If None, calls embedding service.

    Returns:
        True if ingestion succeeded, False otherwise.
    """
    log_uuid = entry_dict.get("log_uuid", "")
    synthetic_intent = entry_dict.get("synthetic_intent", "")

    if not synthetic_intent:
        logger.warning(f"Skipping {log_uuid}: no synthetic_intent")
        return False

    try:
        # Get embedding if not provided
        if embedding is None:
            embedding = await _get_embedding(synthetic_intent)
            if embedding is None:
                logger.error(f"Failed to embed {log_uuid}")
                return False

        # Parse event_timestamp to Unix timestamp
        event_ts = _parse_timestamp(entry_dict.get("event_timestamp", ""))

        # Build metadata dict
        # Ref: §3.2 — "metadata containing log_uuid, event_timestamp as
        # Unix timestamp integer, event_type, source_ip, dest_ip, hostname, severity"
        metadata = {
            "log_uuid": log_uuid,
            "event_timestamp": event_ts,
            "event_type": entry_dict.get("event_type", "UNKNOWN"),
            "hostname": entry_dict.get("hostname", "unknown"),
        }

        # Only add non-None string metadata (ChromaDB doesn't accept None values)
        if entry_dict.get("source_ip"):
            metadata["source_ip"] = entry_dict["source_ip"]
        if entry_dict.get("dest_ip"):
            metadata["dest_ip"] = entry_dict["dest_ip"]
        if entry_dict.get("severity"):
            metadata["severity"] = entry_dict["severity"]

        # Store in ChromaDB active collection
        client = _get_chromadb_client()
        collection = _ensure_collection(client, ACTIVE_COLLECTION)

        collection.upsert(
            ids=[log_uuid],
            documents=[synthetic_intent],
            embeddings=[embedding],
            metadatas=[metadata],
        )

        logger.debug(f"Ingested {log_uuid} into ChromaDB ({ACTIVE_COLLECTION})")
        return True

    except Exception as e:
        logger.error(f"ChromaDB ingestion failed for {log_uuid}: {e}")
        return False


# ─── Batch Ingestion ──────────────────────────────────────────────────────


async def ingest_batch(entries: list[dict]) -> dict:
    """
    Batch ingest multiple NormalizedLogEntry dicts into ChromaDB.

    Uses the /embed-batch endpoint for efficient GPU batching.

    Returns dict with counts: {ingested, failed, skipped}.
    """
    if not entries:
        return {"ingested": 0, "failed": 0, "skipped": 0}

    # Filter entries with valid synthetic_intent
    valid_entries = [e for e in entries if e.get("synthetic_intent", "").strip()]
    skipped = len(entries) - len(valid_entries)

    if not valid_entries:
        return {"ingested": 0, "failed": 0, "skipped": skipped}

    try:
        # Get batch embeddings
        texts = [e["synthetic_intent"] for e in valid_entries]
        embeddings = await _get_embeddings_batch(texts)

        if embeddings is None or len(embeddings) != len(valid_entries):
            logger.error("Batch embedding failed or size mismatch")
            return {"ingested": 0, "failed": len(valid_entries), "skipped": skipped}

        # Prepare ChromaDB batch data
        ids = []
        documents = []
        embedding_list = []
        metadata_list = []

        for entry, emb in zip(valid_entries, embeddings):
            log_uuid = entry.get("log_uuid", "")
            event_ts = _parse_timestamp(entry.get("event_timestamp", ""))

            metadata = {
                "log_uuid": log_uuid,
                "event_timestamp": event_ts,
                "event_type": entry.get("event_type", "UNKNOWN"),
                "hostname": entry.get("hostname", "unknown"),
            }
            if entry.get("source_ip"):
                metadata["source_ip"] = entry["source_ip"]
            if entry.get("dest_ip"):
                metadata["dest_ip"] = entry["dest_ip"]
            if entry.get("severity"):
                metadata["severity"] = entry["severity"]

            ids.append(log_uuid)
            documents.append(entry["synthetic_intent"])
            embedding_list.append(emb)
            metadata_list.append(metadata)

        # Upsert batch into ChromaDB
        client = _get_chromadb_client()
        collection = _ensure_collection(client, ACTIVE_COLLECTION)

        collection.upsert(
            ids=ids,
            documents=documents,
            embeddings=embedding_list,
            metadatas=metadata_list,
        )

        logger.info(f"Batch ingested {len(ids)} entries into ChromaDB")
        return {"ingested": len(ids), "failed": 0, "skipped": skipped}

    except Exception as e:
        logger.error(f"Batch ingestion failed: {e}")
        return {"ingested": 0, "failed": len(valid_entries), "skipped": skipped}


# ─── Helpers ───────────────────────────────────────────────────────────────


def _parse_timestamp(ts_str: str) -> float:
    """Parse ISO8601 timestamp to Unix float. Returns 0.0 on failure."""
    if not ts_str:
        return 0.0
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except (ValueError, TypeError):
        return 0.0


async def _get_embedding(text: str) -> Optional[list[float]]:
    """Call embedding service for a single text."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{EMBEDDING_SERVICE_URL}/embed",
                json={"text": text},
            )
            resp.raise_for_status()
            return resp.json().get("embedding")
    except Exception as e:
        logger.error(f"Embedding service call failed: {e}")
        return None


async def _get_embeddings_batch(texts: list[str]) -> Optional[list[list[float]]]:
    """Call embedding service for a batch of texts."""
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{EMBEDDING_SERVICE_URL}/embed-batch",
                json={"texts": texts},
            )
            resp.raise_for_status()
            return resp.json().get("embeddings")
    except Exception as e:
        logger.error(f"Batch embedding call failed: {e}")
        return None
