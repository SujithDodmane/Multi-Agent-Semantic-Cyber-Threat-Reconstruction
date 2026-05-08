# AEGIS — Complete Project Documentation
## Everything You Need to Build, Test, and Demo the System

> **Document Purpose**: This is the single reference for every task — from environment setup to final demo. It covers what to do in this dev environment AND what to do externally.

---

## Table of Contents
1. [Environment Setup](#1-environment-setup)
2. [External Service Setup (Manual Steps)](#2-external-service-setup)
3. [Phase 0: Repository & Infrastructure](#3-phase-0-repository--infrastructure)
4. [Phase 1: Ingestion Daemon](#4-phase-1-ingestion-daemon)
5. [Phase 2: OpenClaw Orchestration](#5-phase-2-openclaw-orchestration)
6. [Phase 3: Semantic Correlation Engine](#6-phase-3-semantic-correlation-engine)
7. [Phase 4: Output & Knowledge Graph](#7-phase-4-output--knowledge-graph)
8. [Phase 5: Testing Strategy](#8-phase-5-testing-strategy)
9. [Phase 6: Demo Scenarios](#9-phase-6-demo-scenarios)
10. [Implementation Checklist](#10-implementation-checklist)

---

## 1. Environment Setup

### 1.1 Python Version (IN THIS ENVIRONMENT)

**Detected Python installations:**
| Version | Path | Use? |
|---------|------|------|
| 3.14.4 | `python` (default) | ❌ Too new, no PyTorch wheels |
| 3.10.11 | `py -3.10` | ✅ **Primary — use this** |
| 3.8.x | `py -3.8` | ❌ Too old for Pydantic v2 |

**Create virtual environment:**
```powershell
cd d:\Projects\Multi-Agent Semantic Cyber Threat Reconstruction
py -3.10 -m venv .venv
.venv\Scripts\Activate.ps1
python --version  # Should show 3.10.11
```

### 1.2 GPU Compatibility Check (IN THIS ENVIRONMENT)

**Your GPU**: NVIDIA GeForce RTX 4060 Laptop GPU (8188 MiB / 8GB VRAM)
**CUDA Toolkit**: 12.4 — ✅ Compatible
**Compute Capability**: 8.9 — ✅ Supported by PyTorch

**VRAM Budget:**
| Component | VRAM Usage | Notes |
|-----------|-----------|-------|
| BGE-m3 (FP16) | ~1.5 GB | Embedding model |
| Qwen 2.5-7B Q4_K_M | ~4.5 GB | Via Ollama |
| ChromaDB HNSW index | ~0.5 GB | In-memory index |
| PyTorch overhead | ~0.5 GB | CUDA context |
| **Total** | **~7.0 GB** | Fits in 8GB ✅ |

**Verify CUDA with PyTorch (after venv setup):**
```powershell
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124
python -c "import torch; print(f'CUDA: {torch.cuda.is_available()}, Device: {torch.cuda.get_device_name(0)}')"
```

### 1.3 Core Python Dependencies (IN THIS ENVIRONMENT)

```
# Core framework
fastapi>=0.115.0
uvicorn[standard]>=0.34.0
pydantic>=2.10.0

# ML / Embedding
torch>=2.5.0
transformers>=4.46.0
sentence-transformers>=3.3.0

# Vector DB
chromadb>=0.5.0

# Database
sqlalchemy>=2.0.0

# File monitoring
watchdog>=6.0.0

# Circuit breaker
pybreaker>=1.2.0

# Notifications
python-telegram-bot>=21.0
aiohttp>=3.10.0  # For Discord webhooks

# Utilities
pyyaml>=6.0
python-dotenv>=1.0.0
httpx>=0.27.0

# Testing
pytest>=8.0.0
pytest-asyncio>=0.24.0

# Graph UI
flask>=3.1.0
flask-socketio>=5.4.0
```

### 1.4 Node.js Setup (IN THIS ENVIRONMENT)

**Detected**: Node.js v22.20.0 — ✅ Meets ≥22 requirement.

```powershell
node --version    # v22.20.0 ✅
npm --version     # Check npm is available
```

### 1.5 Docker Setup (IN THIS ENVIRONMENT)

**Detected**: Docker 29.1.3 + Docker Compose v2.40.3 — ✅ Ready.

Verify NVIDIA Container Toolkit for GPU passthrough:
```powershell
docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi
```
If this fails, install NVIDIA Container Toolkit.

---

## 2. External Service Setup (MANUAL — OUTSIDE THIS ENVIRONMENT)

### 2.1 Ollama — LLM Runtime

**Status**: Ollama 0.14.3 installed but not running.

**Steps:**
1. Start Ollama service: `ollama serve` (keep running in background)
2. Pull Qwen 2.5 (quantized for 8GB VRAM):
   ```
   ollama pull qwen2.5:7b-instruct-q4_K_M
   ```
3. Verify: `ollama run qwen2.5:7b-instruct-q4_K_M "Hello"` — should get a response
4. Test JSON mode:
   ```
   curl http://localhost:11434/api/generate -d '{"model":"qwen2.5:7b-instruct-q4_K_M","prompt":"List 3 fruits as JSON","format":"json"}'
   ```

### 2.2 Telegram Bot Setup

1. Open Telegram app → search `@BotFather`
2. Send `/newbot` → follow prompts → name it "AEGIS Alert Bot"
3. **Save the Bot Token** (e.g., `7123456789:AAF...`)
4. Create a test group → add the bot to it
5. Send a test message in the group
6. Get Chat ID:
   ```
   curl https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
   ```
   Look for `"chat":{"id":-100XXXXXXXXXX}` — save this number
7. Add to `.env`:
   ```
   TELEGRAM_BOT_TOKEN=7123456789:AAF...
   TELEGRAM_CHAT_ID=-100XXXXXXXXXX
   ```

### 2.3 Discord Webhook Setup

1. Open Discord → go to your test server
2. Server Settings → Integrations → Webhooks → New Webhook
3. Name it "AEGIS Alerts" → select a channel
4. Copy Webhook URL
5. Add to `.env`:
   ```
   DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
   ```

### 2.4 WhatsApp (OPTIONAL — Skip for MVP)

WhatsApp Business API requires Meta Business Suite account and approval process. Recommend implementing Telegram + Discord first, then WhatsApp as a stretch goal.

### 2.5 OpenClaw Framework Setup

1. Install OpenClaw globally:
   ```
   npm install -g openclaw
   ```
2. Verify: `openclaw --version`
3. Initialize in the project:
   ```
   cd openclaw/
   openclaw init
   ```
4. This creates the base HEARTBEAT.md and project structure
5. Configure the HEARTBEAT.md to point to our FastAPI endpoints

### 2.6 GitHub Repository Setup

1. The `.git` is already initialized
2. Add remote: `git remote add origin https://github.com/<user>/aegis.git`
3. Push initial structure after Phase 0 directory creation
4. Set up GitHub Actions (the `.github/workflows/ci.yml` file)

---

## 3. Phase 0: Repository & Infrastructure

### 3.1 Directory Structure Creation (IN THIS ENVIRONMENT)

Full monorepo structure — see implementation_plan.md for the tree.

### 3.2 Core Configuration Files

**`.env.example`** — Template with all env vars:
- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`
- `DISCORD_WEBHOOK_URL`
- `OLLAMA_BASE_URL=http://localhost:11434`
- `CHROMADB_HOST=localhost`, `CHROMADB_PORT=8000`
- `EMBEDDING_SERVICE_URL=http://localhost:8001`
- `SQLITE_DB_PATH=./data/aegis.db`
- `LOG_WATCH_DIRS=./logs`
- `BGE_MODEL_NAME=BAAI/bge-m3`
- `QWEN_MODEL_NAME=qwen2.5:7b-instruct-q4_K_M`
- `QUEUE_MAX_DEPTH=50`
- `SIMILARITY_THRESHOLD=0.72`
- `TEMPORAL_WINDOW_HOURS=2`

**`.gitignore`** — Excludes: `.venv/`, `__pycache__/`, `data/*.db`, `data/chromadb/`, `.env`, `node_modules/`, `*.pyc`, logs/*.log

**`Makefile`** — Shortcuts:
- `make setup` — create venv, install deps
- `make run-ingestion` — start ingestion daemon
- `make run-embedding` — start embedding service
- `make run-graph` — start graph UI
- `make test` — run all tests
- `make docker-up` — docker-compose up
- `make inject-attack` — run attack scenario

### 3.3 Docker Compose (IN THIS ENVIRONMENT)

Five services defined in `infra/docker-compose.yml`:
1. `openclaw` — Node.js image, exposes port 3000
2. `ingestion` — Python 3.10 image
3. `embedding-service` — Python 3.10 + CUDA runtime, GPU access
4. `chromadb` — Official ChromaDB image, port 8000
5. `graph-ui` — Python 3.10 + Flask, port 5000

Shared volumes: SQLite DB, ChromaDB persist directory, log monitoring directory.

### 3.4 Seccomp Profiles (IN THIS ENVIRONMENT)

`infra/seccomp/skill_profile.json` — Restricts:
- No `fork`/`exec` of arbitrary processes
- No network socket creation
- No filesystem writes outside defined paths

---

## 4. Phase 1: Ingestion Daemon (Plane 1)

### 4.1 Key Implementation Details

| Component | File | Critical Notes |
|-----------|------|---------------|
| File Watcher | `ingestion/daemon.py` | Watchdog library, inode-aware rotation, cursor persistence |
| Log Identifier | `ingestion/log_identifier.py` | Path pattern + field signature matching, zero ML |
| Normalizer | `ingestion/normalizer.py` | Canonical JSON schema, UUID4, timestamp parsing |
| Intent Translator | `ingestion/intent_translator.py` | YAML templates, f-string interpolation, entropy calc |
| DB Layer | `ingestion/db.py` | SQLAlchemy + SQLite WAL mode, indexes |
| Priority Queue | `ingestion/priority_queue.py` | asyncio.PriorityQueue, P0-P2 scoring, backpressure |

### 4.2 Canonical Schema Fields (Mandatory)
`log_uuid`, `ingestion_timestamp`, `event_timestamp`, `source_ip`, `dest_ip`, `source_port`, `dest_port`, `process_name`, `parent_process_name`, `user_account`, `event_type`, `event_code`, `hostname`, `sha256_hash`, `raw_payload`, `synthetic_intent`

### 4.3 Event Type Taxonomy
`PROCESS_CREATION`, `NETWORK_CONNECTION`, `FILE_WRITE`, `FILE_DELETE`, `REGISTRY_WRITE`, `DNS_QUERY`, `HTTP_REQUEST`, `AUTHENTICATION_SUCCESS`, `AUTHENTICATION_FAILURE`, `PRIVILEGE_ESCALATION`, `SERVICE_INSTALL`, `SCHEDULED_TASK`, `LATERAL_MOVEMENT_HINT`, `EXFILTRATION_HINT`, `UNKNOWN`

### 4.4 Priority Scoring
- **P0** (0): PRIVILEGE_ESCALATION, EXFILTRATION_HINT, LATERAL_MOVEMENT_HINT, AUTH_FAILURE_BURST
- **P1** (1): PROCESS_CREATION with web server parent, NETWORK_CONNECTION to external on unusual ports
- **P2** (2): All other anomalous events
- **BENIGN**: No anomaly flags → SQLite only, not queued

### 4.5 Intent Template Examples
See implementation plan for all 6 template types. Key: templates live in `ingestion/config/intent_templates.yaml`, are loaded at daemon startup, and use f-string interpolation with null-safe field substitution.

---

## 5. Phase 2: OpenClaw Orchestration (Plane 2)

### 5.1 HEARTBEAT.md Event Loop
- 500ms poll interval
- Non-blocking 200ms timeout on queue endpoint
- Circuit breaker state check on each tick
- Health metric emission

### 5.2 SKILL.md Contracts
Each skill declares: INPUT schema, OUTPUT schema, FAILURE handling, RBAC permissions.

### 5.3 Cognitive RAM Key Naming
- `context:triage:{log_uuid}` — Triage output
- `context:correlation:{log_uuid}` — Correlation output
- `context:timeline:{log_uuid}` — Timeline input
- `context:manifest:{log_uuid}` — Handoff manifest with schema version
- `activity:ip:{ip_address}:{hour_bucket}` — IP activity counters (4hr expiry)

### 5.4 Triage Scoring
| Condition | Points |
|-----------|--------|
| Process in dangerous list (mimikatz, psexec, etc.) | +40 |
| Web server parent + cmd/powershell child | +35 |
| Dest port in C2 list (4444, 5555, 1337, etc.) | +30 |
| Event type = PRIVILEGE_ESCALATION / EXFILTRATION_HINT | +50 |
| IP seen in recent Cognitive RAM context | +20 |

Score mapping: 0-20=BENIGN, 21-40=P2, 41-60=P1, 61+=P0

---

## 6. Phase 3: Semantic Correlation Engine (Plane 3)

### 6.1 Embedding Service Specs
- BGE-m3 model loaded at container startup (15-30s load time)
- Health endpoint returns "ready" only AFTER test embedding succeeds
- Dynamic batching: 50ms collection window, up to 16 texts per batch
- Input validation: non-empty, ≤512 tokens, sentence-boundary truncation

### 6.2 ChromaDB Configuration
- **Hot collection** (`logs_active`): last 72 hours, HNSW ef_construction=200, M=48
- **Cold collection** (`logs_archive`): older than 72 hours
- Metadata per document: log_uuid, event_timestamp, event_type, source_ip, dest_ip, hostname, severity

### 6.3 Correlation Query
- k=20 nearest neighbors
- Temporal pre-filter: ±2 hours (configurable per event_type)
- Cosine similarity threshold: ≥0.72
- Cold start detection: cluster_size=0 → cold_start=true

### 6.4 Qwen 2.5 Integration
- Ollama JSON mode (format="json")
- Temperature: 0.1 primary, 0.05 on retry
- 3-retry fallback → dead-letter queue
- MITRE ATT&CK reference table in system prompt (T1059, T1021, T1055, T1071, T1486, T1003, T1105, T1543, T1505, T1190)

---

## 7. Phase 4: Output & Knowledge Graph (Plane 4)

### 7.1 Report Formatting
- Telegram: Markdown with code blocks for IPs/processes, 4096-char chunking
- Discord: Similar Markdown formatting
- WhatsApp: Plain text (Markdown stripped)

### 7.2 Knowledge Graph (Cytoscape.js)
- **Nodes**: IP, hostname, process, user, file — with threat_score coloring
- **Edges**: network_connection, process_spawn, file_write, authentication
- **Layout**: CoSE-Bilkent (primary), BFS timeline (secondary)
- **Updates**: WebSocket delta-only pushes (not full graph)

### 7.3 Dead-Letter Queue
- SQLite table: dlq_uuid, work_type, payload, failure_reason, failed_at, retry_count, resolved
- Background task: every 5 min, re-submit entries with retry_count < 3 at P1
- After 3 retries: mark resolved=false, notify analyst

---

## 8. Phase 5: Testing Strategy

| Test Type | Scope | When to Run |
|-----------|-------|-------------|
| Unit (normalizer, intent, entropy, scoring) | Ingestion layer | After Phase 1 |
| Integration (full agent chain) | All planes via Docker | After Phase 3 |
| Stress (500 entries/sec × 60s) | Concurrency & backpressure | After Phase 4 |
| Ablation (semantic vs keyword) | Embedding quality proof | After Phase 4 |
| Race condition (dual P0 within 10ms) | Queue serialization | After Phase 4 |

---

## 9. Phase 6: Demo Scenarios

### Scenario 1: Web Shell → Lateral Movement
4-step attack chain: Apache web shell → recon (SMB scan) → credential dump (lsass) → lateral movement to DB server.

### Scenario 2: DNS Tunneling Exfiltration
20 high-entropy DNS queries to same parent domain, demonstrating entropy-based detection.

### Demo Setup
- Pre-seeded ChromaDB with 48hrs synthetic baseline
- Two-screen layout: attacker terminal (left) + graph UI + Telegram (right)
- Attack injection via `scripts/inject_attack.py`

---

## 10. Implementation Checklist

### Plane 1: Ingestion & Normalization
- [ ] Watchdog daemon with inode-aware rotation
- [ ] Log type identification registry
- [ ] Canonical JSON schema in schemas/
- [ ] Intent templates (6 event types + fallback)
- [ ] Shannon entropy for DNS detection
- [ ] Null-field substitution tested
- [ ] SHA-256 hashing on all entries
- [ ] SQLite WAL mode verified
- [ ] Priority queue scoring (P0/P1/P2/BENIGN)
- [ ] Queue backpressure (drop P2 at depth > 50)

### Plane 2: OpenClaw Orchestration
- [ ] HEARTBEAT.md with non-blocking 200ms timeout
- [ ] Triage SKILL.md with configurable threat lists
- [ ] Cognitive RAM key naming with log_uuid
- [ ] IP activity counters with 4-hour expiry
- [ ] RBAC permissions declared per skill
- [ ] Credential vault (no hardcoded secrets)
- [ ] Handoff manifest with schema versioning
- [ ] Schema mismatch → dead-letter (not crash)

### Plane 3: Semantic Correlation
- [ ] BGE-m3 GPU load at startup, health endpoint
- [ ] Dynamic batching (50ms window)
- [ ] 512-token sentence-boundary truncation
- [ ] ChromaDB HNSW (ef=200, M=48)
- [ ] Temporal pre-filter on event_timestamp
- [ ] Cosine threshold ≥0.72
- [ ] Cold start handling
- [ ] Qwen 2.5 JSON mode, temp=0.1/0.05
- [ ] Pydantic validation + 3-retry
- [ ] MITRE ATT&CK in system prompt
- [ ] Circuit breakers (failure=3, recovery=60s)
- [ ] OPEN circuit → dead-letter + analyst alert

### Plane 4: Output & Graph
- [ ] Telegram formatter with 4096-char chunking
- [ ] WhatsApp plain text formatter
- [ ] WebSocket delta-only graph updates
- [ ] Node threat_score coloring (blue/amber/red)
- [ ] CoSE-Bilkent + BFS layouts
- [ ] Dead-letter retry every 5 min
- [ ] 3-retry → resolved=false + analyst alert

### Security
- [ ] Log sanitization before LLM injection
- [ ] Docker read-only mounts for skills
- [ ] Seccomp profiles tested
- [ ] SHA-256 verification on retrieval
- [ ] OpenClaw RBAC enforced
