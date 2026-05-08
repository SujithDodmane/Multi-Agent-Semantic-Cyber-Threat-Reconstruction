# AEGIS — Multi-Agent Semantic Threat Evaluation & Reconstruction

> Fully offline, edge-deployed autonomous SOC analyst platform.

AEGIS (Multi-Agent Semantic Threat Evaluation & Reconstruction) is a state-of-the-art cybersecurity platform designed to automate the forensic reconstruction of cyber attacks. Unlike traditional SIEMs that produce isolated alerts, AEGIS uses a multi-agent orchestration framework to correlate semantic "intents" across time and space, producing a unified forensic story.

---

## 🏛️ Architecture: The Four-Plane Design

AEGIS operates as a four-plane microservice architecture, as detailed in the [Implementation Methodology](docs/methodology_reference.txt):

1.  **Plane 1: Ingestion & Normalization**: Real-time log tailing, greedy normalization, and "Synthetic Intent" translation.
2.  **Plane 2: OpenClaw Orchestration**: A Node.js heartbeat loop managing independent agents (Triage, Correlation, Timeline) via shared Cognitive RAM.
3.  **Plane 3: Semantic Reasoning**: CUDA-accelerated BGE-m3 embeddings and ChromaDB vector search to find behavioral links across a temporal window.
4.  **Plane 4: Output & Visualization**: Real-time 3D Knowledge Graph projection and LLM-synthesized forensic reports delivered via Telegram.

---

## 🛠️ Tech Stack

*   **Orchestration**: OpenClaw (Node.js)
*   **Backend**: Python 3.10+ (FastAPI)
*   **LLM/AI**: Qwen 2.5-7B (Ollama)
*   **Vector Database**: ChromaDB
*   **Embedding Model**: BAAI/BGE-m3
*   **Visualization**: Cytoscape.js

---

## ⚙️ Prerequisites & Setup

### 1. Environment Requirements
*   **Windows 10/11** (Optimized for PowerShell/CMD)
*   **Python 3.10+** (Recommend using a virtual environment named `claw`)
*   **Node.js v20+**
*   **Ollama** (For local LLM inference)
*   **NVIDIA GPU** (Recommended for BGE-m3 embeddings)

### 2. Install Dependencies
```powershell
# Create and activate virtual environment
python -m venv claw
.\claw\Scripts\activate

# Install Python requirements
pip install -r requirements.txt

# Install Node.js dependencies
cd openclaw
npm install
cd ..
```

### 3. Model Setup (Ollama)
```powershell
ollama pull qwen2.5:3b-instruct  # Or your preferred version
```

### 4. Configuration (.env)
Create a `.env` file in the root directory. Use the following as a template:
```ini
# --- Notification Services ---
TELEGRAM_BOT_TOKEN=your_token_here
TELEGRAM_CHAT_ID=your_chat_id_here

# --- Ollama / LLM ---
OLLAMA_BASE_URL=http://localhost:11434
QWEN_MODEL_NAME=qwen2.5:3b-instruct

# --- Service URLs (used by OpenClaw) ---
INGESTION_API_URL=http://localhost:8000
CORRELATION_SERVICE_URL=http://localhost:8003
SYNTHESIZER_SERVICE_URL=http://localhost:8004
NOTIFICATION_SERVICE_URL=http://localhost:8005
GRAPH_SERVICE_URL=http://localhost:5000
```

---

## 🚀 Running the System

### Automated Start (Recommended)
The easiest way to launch the full swarm of services is using the Master Launcher:
```powershell
.\start_aegis.bat
```
*This will open multiple titled terminal windows for each agent and service.*

### Stopping the System
Use the surgical shutdown utility to safely close only AEGIS-related processes:
```powershell
.\stop_aegis.bat
```

---

## 🧪 Demonstration & Testing

### 1. The "Operation BlackMirror" Scenario
We have included a high-fidelity attack scenario (`tests/mixed_realworld_scenario.log`) that simulates a full kill chain: SQLi → Web Shell → C2 Beaconing → Credential Dumping → Ransomware.

### 2. Injecting Logs
To simulate a live attack, use the scenario injector:
```powershell
# Ensure venv is active
python scripts/scenario_injector.py
```

### 3. Monitoring Results
*   **3D Knowledge Graph**: Open your browser to `http://localhost:5000` to see the attack being projected in real-time.
*   **Telegram Alerts**: Check your configured Telegram chat for full forensic narratives and MITRE ATT&CK mapping.
*   **Agent Console**: Monitor the **AEGIS - OPENCLAW ORCHESTRATOR** terminal to see the "Detective" and "Storyteller" agents thinking.

---

## 📂 Project Structure

*   `ingestion/`: Log tailing, greedy normalization, and intent translation.
*   `openclaw/`: Node.js agents, Heartbeat loop, and SKILL definitions.
*   `services/`: FastAPI services for embedding, correlation, and graph projection.
*   `tests/`: Real-world attack scenarios and unit tests.
*   `scripts/`: Automation scripts for launching, stopping, and injecting logs.
*   `docs/`: Detailed methodology and architecture references.

---

## 📜 License
MIT
