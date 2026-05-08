# AEGIS Architecture Documentation

## Four-Plane Architecture

AEGIS operates as a four-plane microservice architecture:

### Plane 1: Ingestion & Normalization
- Python file-tailing daemon (watchdog)
- Canonical JSON normalization
- Synthetic intent translation (natural language for BGE-m3)
- SHA-256 chain-of-custody hashing
- SQLite WAL-mode archival
- asyncio.PriorityQueue with heuristic scoring

### Plane 2: OpenClaw Orchestration
- HEARTBEAT.md continuous event loop (500ms poll)
- Three SKILL.md agents: Triage → Correlation → Timeline
- Cognitive RAM for inter-agent communication
- RBAC and credential vault per skill
- Versioned handoff manifests

### Plane 3: Semantic Correlation & Reasoning
- FastAPI embedding service (BGE-m3, CUDA-accelerated)
- ChromaDB with HNSW indexing (ef=200, M=48)
- Temporal-bounded vector search (±2hr)
- Qwen 2.5-7B via Ollama (JSON mode, temp=0.1)
- Pydantic validation with 3-retry fallback
- MITRE ATT&CK mapping

### Plane 4: Output & Persistence
- Forensic report formatting (Telegram/Discord/WhatsApp)
- Cytoscape.js knowledge graph (CoSE-Bilkent layout)
- WebSocket delta-only graph updates
- Dead-letter queue with retry management

## Data Flow

```
Log File → Watchdog → Normalize → Intent Translate → SHA-256 → SQLite
                                                               ↓
                                                    Priority Queue
                                                               ↓
                                              HEARTBEAT.md poll
                                                               ↓
                                              Triage SKILL.md
                                                               ↓
                                           Correlation SKILL.md
                                                    ↓
                                    FastAPI /embed → ChromaDB query
                                                               ↓
                                              Timeline SKILL.md
                                                    ↓
                                        Qwen 2.5 → Pydantic validate
                                                               ↓
                                    ┌──────────────┴──────────────┐
                              Telegram/Discord              Cytoscape.js
                               (mobile alert)              (graph update)
```
