# Timeline SKILL — Forensic Narrative Synthesis

## Metadata
- **Name:** AEGIS Timeline Agent
- **Version:** 1.0.0
- **Description:** Generates forensic investigation reports by synthesizing correlated log clusters via Qwen 2.5 LLM. The most complex component in the agent chain.
- **RBAC Permissions:**
  - READ: Cognitive RAM (context namespace)
  - WRITE: Cognitive RAM (context namespace)
  - NETWORK: Python Synthesizer Service (`POST http://localhost:8004/synthesize`)

## Input
1. Read handoff manifest from: `context:manifest:{log_uuid}`
   - Validate `schema_version` matches expected "1.0.0"
   - Validate `from_skill` is "correlation"
   - If mismatch: dead-letter queue, DO NOT crash
2. Read correlation context from: `context:timeline:{log_uuid}`
   - Contains: triggering_log + correlation output (cluster, cold_start flag)

## Logic

### Step 1: Validate Handoff
```
manifest = read("context:manifest:{log_uuid}")
if manifest.schema_version != "1.0.0" || manifest.from_skill != "correlation":
    dead_letter_queue.add(log_uuid, "invalid_manifest")
    return
```

### Step 2: Call Python Synthesizer Service
HTTP POST to `http://localhost:8004/synthesize`:
```json
{
  "triggering_log": { "...NormalizedLogEntry..." },
  "correlated_cluster": [
    {
      "synthetic_intent": "...",
      "cosine_similarity": 0.89,
      "event_timestamp": "2026-05-07T09:58:00Z",
      "event_type": "NETWORK_CONNECTION",
      "mitre_technique_hint": "T1021"
    }
  ],
  "cold_start": false
}
```

The Python service internally:
- Constructs Qwen 2.5 prompt with MITRE ATT&CK reference table
- Calls Ollama with `format="json"`, `temperature=0.1`
- Validates response with Pydantic `ForensicReport` model
- Retries up to 3 times (temp 0.1 → 0.05 → 0.05)
- Returns validated forensic report or error

### Step 3: Handle Cold Start
If `cold_start == true`, the synthesizer generates a report with:
- Label: "Initial Detection — No Historical Context Available"
- Confidence: < 0.5
- Narrative based solely on triggering log entry
- Note about insufficient baseline data

### Step 4: Deliver Report
On successful synthesis:
1. **Telegram/Discord:** Format report via Protocol Adapter
   - Severity header (P0 CRITICAL / P1 HIGH / P2 MEDIUM)
   - Narrative paragraph
   - Timeline events (chronological)
   - Entities list (IPs, processes, users)
   - MITRE ATT&CK techniques
   - Confidence percentage
   - Report ID for cross-reference with knowledge graph
2. **Knowledge Graph:** Push report to Graph WebSocket server for Cytoscape.js update
3. **Cleanup:** Delete all Cognitive RAM keys for this `log_uuid`:
   - `context:triage:{log_uuid}`
   - `context:correlation:{log_uuid}`
   - `context:timeline:{log_uuid}`
   - `context:manifest:{log_uuid}`

## Output
ForensicReport delivered via Protocol Adapter:
```json
{
  "narrative": "A web shell execution was detected on WEBSERVER01...",
  "confidence": 0.87,
  "mitre_tactics": ["Initial Access", "Execution", "Lateral Movement"],
  "mitre_techniques": ["T1505.003", "T1059.003", "T1021.002"],
  "entities": [
    {"type": "hostname", "value": "WEBSERVER01", "role": "victim"},
    {"type": "process", "value": "cmd.exe", "role": "attacker_tool"}
  ],
  "timeline_events": [
    {"timestamp": "2026-05-07T09:55:00Z", "description": "Web shell executed", "severity": "P0"}
  ],
  "root_cause": "Compromised web application on WEBSERVER01",
  "report_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

## Failure Handling
- **Synthesizer returns `success: false`:** Entry goes to dead-letter queue with failure_reason
- **HTTP 503 (Ollama down):** Circuit breaker OPEN → dead-letter + analyst degradation notification
- **3 retries exhausted:** Mark as unresolvable, notify analyst with raw cluster for manual review
- **Telegram 4096-char limit:** Chunk report at section boundaries, include part indicators (1/3, 2/3, etc.)

## Message Format (Telegram Markdown)
```
⚠️ **P0 CRITICAL ALERT**

{narrative}

📋 **Timeline:**
- `{timestamp}` — {description}

🎯 **Entities:**
- `{ip}` — {role}
- `{process}` — {role}

🛡️ **MITRE ATT&CK:**
- {technique_id}: {technique_name}

📊 **Confidence:** {confidence}%
🔗 **Report ID:** `{report_id}`
```
