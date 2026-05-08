# Triage SKILL — Heuristic Anomaly Scoring

## Metadata
- **Name:** AEGIS Triage Agent
- **Version:** 1.0.0
- **Description:** Evaluates log entries against heuristic flag conditions to classify severity. Pure synchronous computation — no external service calls.
- **RBAC Permissions:**
  - READ: Cognitive RAM (context namespace)
  - WRITE: Cognitive RAM (context namespace, activity namespace)
  - NETWORK: None (no external calls)

## Input
Reads a `NormalizedLogEntry` from Cognitive RAM key: `context:triage:{log_uuid}`

The entry contains these fields for scoring:
- `process_name` — Name of the executed process
- `parent_process_name` — Name of the parent process
- `dest_port` — Destination port number
- `event_type` — Taxonomy classification (PROCESS_CREATION, NETWORK_CONNECTION, etc.)
- `source_ip`, `dest_ip` — IP addresses involved
- `log_uuid` — Unique identifier for this entry

## Logic

### Step 1: Load Threat Intelligence
Load configurable threat lists from `openclaw/config/threat_lists.yaml`:
- `dangerous_processes`: Known attacker tools (mimikatz, procdump, psexec, etc.)
- `c2_ports`: Known command-and-control ports (4444, 5555, 1337, etc.)
- `scoring_weights`: Points per condition
- `severity_thresholds`: Score boundaries for P0/P1/P2/BENIGN

### Step 2: Evaluate Decision Tree
Calculate cumulative severity score by evaluating these flag conditions:

| # | Condition | Points | Rationale |
|---|-----------|--------|-----------|
| 1 | `process_name` is in `dangerous_processes` list | +40 | Known attacker tools |
| 2 | `parent_process_name` is a web server (apache2, nginx, w3wp.exe, tomcat, httpd) AND `process_name` is cmd.exe or powershell.exe | +35 | Web shell execution |
| 3 | `dest_port` is in `c2_ports` list | +30 | C2 communication channel |
| 4 | `event_type` is PRIVILEGE_ESCALATION or EXFILTRATION_HINT | +50 | Critical event types |
| 5 | `source_ip` or `dest_ip` appears in recent Cognitive RAM IP activity counters | +20 | Historical correlation |

### Step 3: Classify Severity
Map cumulative score to severity classification:
- **Score 0-20:** BENIGN — do not escalate
- **Score 21-40:** P2 (Medium) — correlation optional
- **Score 41-60:** P1 (High) — correlation required
- **Score 61+:** P0 (Critical) — correlation required + immediate alert

### Step 4: Update IP Activity Counters
For each `source_ip` and `dest_ip` in the entry:
- Increment counter at `activity:ip:{ip_address}:{hour_bucket}` in Cognitive RAM
- Counters expire after 4 hours
- Used by Step 2, Condition 5 for historical correlation scoring

### Step 5: On P0 — Immediate Alert
If severity is P0, trigger Protocol Adapter to send an initial alert via Telegram/Discord BEFORE correlation completes. Message format:
```
⚠️ P0 CRITICAL ALERT (Pre-Correlation)
Host: {hostname}
Event: {synthetic_intent}
Score: {cumulative_score}
Investigation in progress...
```

## Output
Write `TriageOutput` to Cognitive RAM key: `context:correlation:{log_uuid}`

```json
{
  "anomaly_detected": true,
  "severity": "P0",
  "heuristic_flags": ["dangerous_process:mimikatz", "c2_port:4444"],
  "correlation_required": true,
  "confidence": 0.85
}
```

Also write handoff manifest to: `context:manifest:{log_uuid}`
```json
{
  "log_uuid": "...",
  "from_skill": "triage",
  "schema_version": "1.0.0",
  "timestamp": "2026-05-07T10:00:00Z"
}
```

## Failure Handling
- If scoring throws an exception: write entry to dead-letter queue, do not crash
- If Cognitive RAM write fails: retry once, then dead-letter
- BENIGN entries: do NOT write to correlation context (pipeline stops here)
