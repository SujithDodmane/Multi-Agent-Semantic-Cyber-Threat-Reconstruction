"""
AEGIS — ChromaDB Collection Manager

Manages the dual-collection hot/cold architecture:
  - logs_active (hot): Last 72 hours, HNSW ef=200, M=48
  - logs_archive (cold): Older than 72 hours

Provides collection lifecycle management:
  - Initialize collections with correct HNSW parameters
  - Hourly hot→cold migration of aged entries
  - Collection statistics for monitoring

Ref: Methodology §3.2 — ChromaDB Collection Design
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timezone

logger = logging.getLogger("aegis.collection_manager")

# ─── Configuration ─────────────────────────────────────────────────────────

CHROMADB_HOST = os.getenv("CHROMADB_HOST", "localhost")
CHROMADB_PORT = int(os.getenv("CHROMADB_PORT", "8000"))
ACTIVE_COLLECTION = "logs_active"
ARCHIVE_COLLECTION = "logs_archive"

# 72 hours in seconds — entries older than this are moved to archive
HOT_WINDOW_SECONDS = int(os.getenv("HOT_WINDOW_HOURS", "72")) * 3600

# HNSW parameters per §3.2
HNSW_PARAMS = {
    "hnsw:construction_ef": 200,
    "hnsw:M": 48,
}


def _get_client():
    """Get ChromaDB HTTP client."""
    import chromadb
    return chromadb.HttpClient(host=CHROMADB_HOST, port=CHROMADB_PORT)


# ─── Collection Initialization ─────────────────────────────────────────────


def initialize_collections() -> dict:
    """
    Initialize both collections with correct HNSW parameters.

    Ref: §3.2 — "ef_construction=200, M=48. These values produce an index
    that balances search speed and recall. For collections up to 1 million
    entries, these settings provide O(log N) query performance with recall
    above 95%."

    Returns dict with collection stats.
    """
    try:
        client = _get_client()

        active = client.get_or_create_collection(
            name=ACTIVE_COLLECTION,
            metadata=HNSW_PARAMS,
        )

        archive = client.get_or_create_collection(
            name=ARCHIVE_COLLECTION,
            metadata=HNSW_PARAMS,
        )

        stats = {
            "active_count": active.count(),
            "archive_count": archive.count(),
            "hnsw_ef_construction": 200,
            "hnsw_M": 48,
        }

        logger.info(
            f"Collections initialized — "
            f"active: {stats['active_count']}, "
            f"archive: {stats['archive_count']}"
        )
        return stats

    except Exception as e:
        logger.error(f"Failed to initialize collections: {e}")
        return {"error": str(e)}


# ─── Hot → Cold Migration ─────────────────────────────────────────────────


def migrate_old_entries() -> dict:
    """
    Move entries older than 72 hours from logs_active to logs_archive.

    This keeps the hot index small and fast for correlation queries.
    The cold archive is available for historical forensic review.

    Returns dict with migration stats.
    """
    try:
        client = _get_client()
        active = client.get_or_create_collection(
            name=ACTIVE_COLLECTION,
            metadata=HNSW_PARAMS,
        )
        archive = client.get_or_create_collection(
            name=ARCHIVE_COLLECTION,
            metadata=HNSW_PARAMS,
        )

        if active.count() == 0:
            return {"migrated": 0, "active_remaining": 0}

        # Find entries older than the hot window
        cutoff_ts = time.time() - HOT_WINDOW_SECONDS

        # Get all entries and filter (ChromaDB doesn't support delete-by-filter well)
        # For large collections, this should be paginated
        results = active.get(
            include=["documents", "embeddings", "metadatas"],
            limit=1000,
        )

        if not results or not results["ids"]:
            return {"migrated": 0, "active_remaining": active.count()}

        # Identify entries to migrate
        migrate_ids = []
        migrate_docs = []
        migrate_embeddings = []
        migrate_metadatas = []

        for i, entry_id in enumerate(results["ids"]):
            metadata = results["metadatas"][i] if results["metadatas"] else {}
            event_ts = metadata.get("event_timestamp", 0)

            try:
                if float(event_ts) < cutoff_ts:
                    migrate_ids.append(entry_id)
                    migrate_docs.append(
                        results["documents"][i] if results["documents"] else ""
                    )
                    if results["embeddings"]:
                        migrate_embeddings.append(results["embeddings"][i])
                    migrate_metadatas.append(metadata)
            except (ValueError, TypeError):
                continue

        if not migrate_ids:
            return {"migrated": 0, "active_remaining": active.count()}

        # Upsert into archive
        upsert_kwargs = {
            "ids": migrate_ids,
            "documents": migrate_docs,
            "metadatas": migrate_metadatas,
        }
        if migrate_embeddings:
            upsert_kwargs["embeddings"] = migrate_embeddings

        archive.upsert(**upsert_kwargs)

        # Delete from active
        active.delete(ids=migrate_ids)

        logger.info(
            f"Migrated {len(migrate_ids)} entries from "
            f"{ACTIVE_COLLECTION} → {ARCHIVE_COLLECTION}"
        )

        return {
            "migrated": len(migrate_ids),
            "active_remaining": active.count(),
            "archive_total": archive.count(),
        }

    except Exception as e:
        logger.error(f"Migration failed: {e}")
        return {"error": str(e)}


# ─── Collection Stats ─────────────────────────────────────────────────────


def get_collection_stats() -> dict:
    """Get statistics for both collections."""
    try:
        client = _get_client()

        active = client.get_or_create_collection(
            name=ACTIVE_COLLECTION,
            metadata=HNSW_PARAMS,
        )
        archive = client.get_or_create_collection(
            name=ARCHIVE_COLLECTION,
            metadata=HNSW_PARAMS,
        )

        return {
            "active": {
                "name": ACTIVE_COLLECTION,
                "count": active.count(),
                "hnsw_ef": 200,
                "hnsw_M": 48,
                "hot_window_hours": HOT_WINDOW_SECONDS // 3600,
            },
            "archive": {
                "name": ARCHIVE_COLLECTION,
                "count": archive.count(),
            },
        }

    except Exception as e:
        return {"error": str(e)}


# ─── Background Migration Task ────────────────────────────────────────────


async def migration_loop(interval_hours: float = 1.0):
    """
    Background task that runs hot→cold migration every hour.

    Start this as an asyncio task in the main service.
    """
    interval_seconds = interval_hours * 3600
    logger.info(f"Migration loop started (interval: {interval_hours}h)")

    while True:
        await asyncio.sleep(interval_seconds)
        try:
            result = migrate_old_entries()
            if result.get("migrated", 0) > 0:
                logger.info(f"Migration result: {result}")
        except Exception as e:
            logger.error(f"Migration loop error: {e}")
