# AEGIS — System Memory

## System Identity
- **Name:** AEGIS (Multi-Agent Semantic Threat Evaluation & Reconstruction)
- **Role:** Autonomous SOC forensic analyst
- **Architecture:** Four-plane microservice (Ingestion → Orchestration → Correlation → Output)

## Threat Intelligence Version
- **Dangerous process list:** v1.0 (mimikatz, procdump, psexec, wce, fgdump, gsecdump, lsass, ntdsutil, lazagne, rubeus, sharphound)
- **C2 port list:** v1.0 (4444, 5555, 1337, 8888, 9001, 6666, 6667, 31337, 12345)
- **Config file:** `openclaw/config/threat_lists.yaml`

## Service Endpoints (Credential Vault)
- **Ingestion Queue API:** `http://localhost:8000` (Python FastAPI)
- **Embedding Service:** `http://localhost:8001` (Python FastAPI + CUDA)
- **Correlation Service:** `http://localhost:8003` (Python FastAPI + ChromaDB)
- **Synthesizer Service:** `http://localhost:8004` (Python FastAPI + Ollama)
- **ChromaDB:** `http://localhost:8000`
- **Ollama:** `http://localhost:11434`

## MITRE ATT&CK Reference
Key techniques for endpoint and network log analysis:
- T1059: Command and Scripting Interpreter
- T1021: Remote Services
- T1055: Process Injection
- T1071: Application Layer Protocol
- T1486: Data Encrypted for Impact
- T1003: OS Credential Dumping
- T1105: Ingress Tool Transfer
- T1543: Create or Modify System Process
- T1505: Server Software Component
- T1190: Exploit Public-Facing Application

## Scoring Thresholds
- **P0 (Critical):** Score ≥ 61
- **P1 (High):** Score 41-60
- **P2 (Medium):** Score 21-40
- **BENIGN:** Score 0-20

## Circuit Breaker Config
- **failure_threshold:** 3 consecutive failures → OPEN
- **recovery_timeout:** 60 seconds → HALF-OPEN
- **Expected exceptions:** Timeout, ConnectionError (NOT 400 Bad Request)

## Schema Versions
- **NormalizedLogEntry:** v1.0.0
- **TriageOutput:** v1.0.0
- **CorrelationOutput:** v1.0.0
- **ForensicReport:** v1.0.0
