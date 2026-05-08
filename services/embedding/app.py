"""
AEGIS — BGE-m3 Embedding Service (GPU-Accelerated)

Standalone FastAPI service with CUDA runtime for generating semantic embeddings.
This is the core AI compute engine that powers AEGIS's semantic correlation.

Architecture: Node.js (OpenClaw) for I/O, Python for Math.
This service IS the "math" — it owns GPU memory and tensor operations.

Key features:
  - BGE-m3 model loaded into GPU at startup (not first request) [§3.1]
  - Dynamic batching: 50ms collection window for up to 16x throughput [§3.1]
  - 512-token limit with sentence-boundary truncation [§3.1]
  - Health endpoint returns 'ready' only after test embedding succeeds [§3.1]

Endpoints:
  POST /embed       — Single text → 384-dim vector
  POST /embed-batch — Text list → vector list
  GET  /health      — Ready after model warmup

Ref: Methodology §3.1 — FastAPI Embedding Service
Ref: TABLE 15 Pitfall — "Always embed synthetic_intent field, never raw_payload"
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger("aegis.embedding")

# ─── Configuration ─────────────────────────────────────────────────────────

MODEL_NAME = os.getenv("EMBEDDING_MODEL", "BAAI/bge-m3")
EMBEDDING_DIM = 1024
MAX_TOKENS = 512
BATCH_WINDOW_MS = int(os.getenv("BATCH_WINDOW_MS", "50"))
MAX_BATCH_SIZE = int(os.getenv("MAX_BATCH_SIZE", "16"))

# ─── Global Model State ───────────────────────────────────────────────────

_model = None
_device = None
_model_ready = False
_batch_queue: Optional[asyncio.Queue] = None
_batch_task: Optional[asyncio.Task] = None


# ─── Sentence-Boundary Truncation ──────────────────────────────────────────

# Ref: §3.1 — "Text longer than 512 tokens is truncated at the sentence
# boundary closest to the limit — not mid-word."
SENTENCE_BOUNDARY_RE = re.compile(r'[.!?]\s+')


def truncate_at_sentence_boundary(text: str, max_chars: int = 2000) -> str:
    """
    Truncate text at the nearest sentence boundary before max_chars.

    We use a character-based approximation (avg ~4 chars per token for English)
    since exact tokenization is expensive. 512 tokens ≈ 2000 chars.

    A sentence-boundary truncation keeps the embedding semantically coherent,
    unlike mid-word truncation which corrupts it.
    """
    if len(text) <= max_chars:
        return text

    # Find all sentence boundaries
    boundaries = [m.end() for m in SENTENCE_BOUNDARY_RE.finditer(text[:max_chars])]

    if boundaries:
        # Truncate at the last sentence boundary before the limit
        return text[:boundaries[-1]].strip()

    # No sentence boundary found — truncate at last space (avoid mid-word)
    last_space = text[:max_chars].rfind(' ')
    if last_space > 0:
        return text[:last_space].strip()

    # Absolute fallback — hard truncate
    return text[:max_chars].strip()


# ─── Dynamic Batch Worker ──────────────────────────────────────────────────

class EmbedRequest:
    """Internal request for the batch queue."""
    def __init__(self, text: str, future: asyncio.Future):
        self.text = text
        self.future = future


async def _batch_worker():
    """
    Background worker that collects embedding requests over a configurable
    window and processes them together as a single GPU batch.

    Ref: §3.1 — "Dynamic batching is the key performance mechanism. Rather
    than processing embedding requests one at a time, the service collects
    incoming requests over a configurable window (default 50ms) and processes
    them together as a batch GPU call."
    """
    global _batch_queue
    while True:
        batch: list[EmbedRequest] = []

        # Wait for at least one request
        try:
            first = await asyncio.wait_for(
                _batch_queue.get(), timeout=1.0
            )
            batch.append(first)
        except asyncio.TimeoutError:
            continue

        # Collect more requests within the batch window
        deadline = time.monotonic() + (BATCH_WINDOW_MS / 1000.0)
        while len(batch) < MAX_BATCH_SIZE and time.monotonic() < deadline:
            try:
                remaining = max(0.001, deadline - time.monotonic())
                item = await asyncio.wait_for(
                    _batch_queue.get(), timeout=remaining
                )
                batch.append(item)
            except asyncio.TimeoutError:
                break

        # Process the batch
        if not batch:
            continue

        texts = [req.text for req in batch]
        try:
            embeddings = await asyncio.get_event_loop().run_in_executor(
                None, _encode_batch, texts
            )
            for req, emb in zip(batch, embeddings):
                if not req.future.done():
                    req.future.set_result(emb)
        except Exception as e:
            for req in batch:
                if not req.future.done():
                    req.future.set_exception(e)


def _encode_batch(texts: list[str]) -> list[list[float]]:
    """Synchronous batch encoding on GPU. Called from executor."""
    if _model is None:
        raise RuntimeError("Model not loaded")

    embeddings = _model.encode(
        texts,
        normalize_embeddings=True,
        show_progress_bar=False,
        batch_size=len(texts),
    )
    return [emb.tolist() for emb in embeddings]


# ─── Model Loading & Startup ──────────────────────────────────────────────

def _load_model():
    """
    Load BGE-m3 into GPU memory.

    Ref: §3.1 — "The BGE-m3 model is loaded into GPU memory when the
    container starts, not on the first request."
    """
    global _model, _device, _model_ready

    try:
        import torch
        from sentence_transformers import SentenceTransformer

        # Detect device
        if torch.cuda.is_available():
            _device = "cuda"
            gpu_name = torch.cuda.get_device_name(0)
            gpu_mem = torch.cuda.get_device_properties(0).total_memory / (1024**3)
            logger.info(f"CUDA available: {gpu_name} ({gpu_mem:.1f} GB)")
        else:
            _device = "cpu"
            logger.warning("CUDA not available — falling back to CPU (SLOW)")

        logger.info(f"Loading {MODEL_NAME} on {_device}...")
        start = time.time()

        _model = SentenceTransformer(MODEL_NAME, device=_device)

        load_time = time.time() - start
        logger.info(f"Model loaded in {load_time:.1f}s")

        # Warmup — generate a test embedding to verify the pipeline works
        # Ref: §3.1 — "health-check endpoint returns 'ready' only after
        # the model is loaded and a test embedding has been generated"
        test_emb = _model.encode(
            ["AEGIS warmup: test embedding"],
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        actual_dim = len(test_emb[0])
        logger.info(f"Warmup complete. Embedding dim: {actual_dim}")

        if actual_dim != EMBEDDING_DIM:
            logger.warning(
                f"Expected {EMBEDDING_DIM}-dim, got {actual_dim}-dim. "
                f"Updating EMBEDDING_DIM."
            )

        _model_ready = True
        logger.info("✅ Embedding service READY")

    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        _model_ready = False
        raise


# ─── FastAPI Lifespan ──────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load model on startup, cleanup on shutdown."""
    global _batch_queue, _batch_task

    # Load model (blocking — runs before first request)
    _load_model()

    # Start batch worker
    _batch_queue = asyncio.Queue()
    _batch_task = asyncio.create_task(_batch_worker())

    yield

    # Cleanup
    if _batch_task:
        _batch_task.cancel()


app = FastAPI(
    title="AEGIS Embedding Service",
    description="BGE-m3 GPU-accelerated embedding service for semantic correlation",
    version="1.0.0",
    lifespan=lifespan,
)


# ─── Request/Response Models ───────────────────────────────────────────────

class EmbedRequestModel(BaseModel):
    """Request body for POST /embed."""
    text: str = Field(description="Synthetic intent text to embed")


class EmbedResponse(BaseModel):
    """Response from POST /embed."""
    embedding: list[float]
    dim: int
    truncated: bool = False


class EmbedBatchRequest(BaseModel):
    """Request body for POST /embed-batch."""
    texts: list[str] = Field(description="List of synthetic intent texts")


class EmbedBatchResponse(BaseModel):
    """Response from POST /embed-batch."""
    embeddings: list[list[float]]
    dim: int
    count: int
    truncated_indices: list[int] = Field(default_factory=list)


# ─── Endpoints ─────────────────────────────────────────────────────────────

@app.post("/embed", response_model=EmbedResponse)
async def embed(request: EmbedRequestModel):
    """
    Generate a single embedding for a synthetic_intent string.

    Ref: §3.1 — "POST /embed accepts a synthetic_intent string
    and returns a 384-dimensional float array"
    """
    if not _model_ready:
        raise HTTPException(status_code=503, detail="Model not ready")

    # Validate input
    text = request.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Text must not be empty")

    # Apply sentence-boundary truncation if needed
    truncated = False
    original_len = len(text)
    text = truncate_at_sentence_boundary(text)
    if len(text) < original_len:
        truncated = True

    # Submit to batch queue
    future = asyncio.get_event_loop().create_future()
    await _batch_queue.put(EmbedRequest(text, future))

    # Wait for result
    embedding = await future

    return EmbedResponse(
        embedding=embedding,
        dim=len(embedding),
        truncated=truncated,
    )


@app.post("/embed-batch", response_model=EmbedBatchResponse)
async def embed_batch(request: EmbedBatchRequest):
    """
    Generate embeddings for a batch of synthetic_intent strings.

    Ref: §3.1 — "POST /embed-batch accepts a list of synthetic_intent
    strings and returns a list of float arrays"
    """
    if not _model_ready:
        raise HTTPException(status_code=503, detail="Model not ready")

    if not request.texts:
        raise HTTPException(status_code=400, detail="Texts list must not be empty")

    # Validate and truncate each text
    processed_texts = []
    truncated_indices = []
    for i, text in enumerate(request.texts):
        text = text.strip()
        if not text:
            raise HTTPException(
                status_code=400,
                detail=f"Text at index {i} must not be empty"
            )
        original_len = len(text)
        text = truncate_at_sentence_boundary(text)
        if len(text) < original_len:
            truncated_indices.append(i)
        processed_texts.append(text)

    # Submit all to batch queue and collect futures
    futures = []
    for text in processed_texts:
        future = asyncio.get_event_loop().create_future()
        await _batch_queue.put(EmbedRequest(text, future))
        futures.append(future)

    # Wait for all results
    embeddings = await asyncio.gather(*futures)

    return EmbedBatchResponse(
        embeddings=list(embeddings),
        dim=len(embeddings[0]) if embeddings else EMBEDDING_DIM,
        count=len(embeddings),
        truncated_indices=truncated_indices,
    )


@app.get("/health")
async def health():
    """
    Health check — returns 'ready' only after model is loaded and warmed up.

    Ref: §3.1 — "The health-check endpoint at GET /health returns 'ready'
    only after the model is loaded and a test embedding has been generated"
    """
    if not _model_ready:
        return {
            "status": "loading",
            "model": MODEL_NAME,
            "device": _device or "unknown",
        }

    import torch
    gpu_info = {}
    if torch.cuda.is_available():
        gpu_info = {
            "gpu_name": torch.cuda.get_device_name(0),
            "gpu_memory_allocated_mb": round(
                torch.cuda.memory_allocated(0) / (1024**2), 1
            ),
            "gpu_memory_reserved_mb": round(
                torch.cuda.memory_reserved(0) / (1024**2), 1
            ),
        }

    return {
        "status": "ready",
        "model": MODEL_NAME,
        "device": _device,
        "embedding_dim": EMBEDDING_DIM,
        "max_tokens": MAX_TOKENS,
        "batch_window_ms": BATCH_WINDOW_MS,
        **gpu_info,
    }
