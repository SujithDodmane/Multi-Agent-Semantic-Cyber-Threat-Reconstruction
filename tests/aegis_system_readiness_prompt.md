# AEGIS — Full Scenario Test: System Readiness Prompt & Integration Guide

## What This Document Is

This document tells you exactly what changes to make to AEGIS before running the
`aegis_threat_scenario.log` file through the pipeline. It covers every log type in
the scenario, what the normalizer and intent translator must handle, what the triage
scorer must flag, and how to verify the full chain is working correctly.

Read this top to bottom before injecting a single log.

---

## 1. Log Types in the Scenario — Normalizer Coverage Check

The scenario contains six distinct log source types. Your `log_identifier.py` and
`normalizer.py` must handle all of them. Run this check first.

### 1.1 Sysmon Events

**Sysmon Event IDs present in the scenario:**

| Event ID | Name | What it means |
|----------|------|---------------|
| 1 | Process Create | Process spawned — parent/child chain |
| 3 | Network Connection | Outbound network connection initiated |
| 10 | Process Access | One process opened a handle to another |
| 11 | File Create | File written to disk |
| 12/13 | Registry Event | Registry key created or value set |

**Normalizer check:** Your `normalizer.py` Sysmon handler must extract these fields
from Event ID 1: `Image` → `process_name`, `ParentImage` → `parent_process_name`,
`CommandLine` → `command_line_args`, `User` → `user_account`, `IntegrityLevel`
(map "System" → flag for escalation check). From Event ID 3: `DestinationIp` →
`dest_ip`, `DestinationPort` → `dest_port`, `SourceIp` → `source_ip`. From
Event ID 10: `SourceImage` → `process_name`, `TargetImage` must be stored in
`command_line_args` or a custom field — the LSASS access detection depends on this.
From Event ID 11: `TargetFilename` → `file_path`. From Event ID 13: `TargetObject`
→ `registry_key`, `Details` → `command_line_args`.

**Action required if broken:** Add `EventID` dispatch branching in `normalizer.py`
for IDs 10 and 13 if not already present. The scenario uses both heavily.

### 1.2 Windows Event Log

**Windows Event IDs present in the scenario:**

| Event ID | Name | Expected Classification |
|----------|------|------------------------|
| 4624 | Logon Success | AUTH_SUCCESS (benign unless LogonType=3 from external IP) |
| 4625 | Logon Failure | AUTH_FAILURE → burst detection |
| 4648 | Explicit Credential Logon | LATERAL_MOVEMENT_HINT |
| 4656 | Handle Request | PRIVILEGE_ESCALATION (if target=lsass) |
| 4657 | Registry Value Modified | FILE_WRITE (registry) |
| 4672 | Special Privileges Assigned | PRIVILEGE_ESCALATION |
| 4688 | Process Creation | PROCESS_CREATION |
| 4698 | Scheduled Task Created | SCHEDULED_TASK |
| 7045 | Service Installed | SERVICE_INSTALL |
| 1102 | Security Log Cleared | EXFILTRATION_HINT (treat as P0) |
| 104 | System Log Cleared | EXFILTRATION_HINT |
| 4104 | PowerShell Script Block | PROCESS_CREATION with extra context |

**Action required:** Verify your `normalizer.py` Windows Event handler maps
Event ID 1102 and 104 (log clearing) to `event_type = EXFILTRATION_HINT`. These
are some of the most critical events in the scenario and must not be classified
as UNKNOWN.

### 1.3 Zeek Network Logs

**Zeek log streams present:**

| Stream (`_path`) | Fields to extract |
|-----------------|------------------|
| `conn` | `id.orig_h`→`source_ip`, `id.resp_h`→`dest_ip`, `id.resp_p`→`dest_port`, `orig_bytes`, `resp_bytes`, `proto`, `service` |
| `dns` | `id.orig_h`→`source_ip`, `query`→`dns_query`, `qtype_name`, `answers` |
| `http` | `id.orig_h`→`source_ip`, `id.resp_h`→`dest_ip`, `method`→`http_method`, `uri`→`http_url`, `status_code`, `user_agent`, `host` |
| `ssl` | `id.orig_h`→`source_ip`, `id.resp_h`→`dest_ip`, `server_name`→`dns_query` (for SNI tracking) |

**Action required:** If your Zeek normalizer only handles `conn` and `dns`, add
handlers for `http` and `ssl`. The HTTP logs carry the SQLi detection, web shell
confirmation, and exfiltration evidence. The SSL logs carry C2 server name
indicators.

### 1.4 Firewall Logs

**Fields present:** `action` (ALLOW/DENY), `src_ip`, `dst_ip`, `src_port`,
`dst_port`, `protocol`, `bytes_sent`, `rule`.

**Classification logic needed:**
- DENY + same `src_ip` across 15+ entries in 60 seconds → PROCESS_CREATION
  equivalent: classify as `NETWORK_CONNECTION` with `mitre_technique_hint = T1046`
- ALLOW + `dst_ip` in known C2 list + `dst_port` in (443, 8443, 4444, 5555) →
  `NETWORK_CONNECTION` with `mitre_technique_hint = T1071`
- ALLOW + `bytes_sent` > 10MB → `EXFILTRATION_HINT`

---

## 2. Synthetic Intent Template Additions

Your current `intent_templates.yaml` covers six event types. The scenario
introduces several patterns that need template coverage or the fallback will
be used, degrading embedding quality. Add these templates before running the test.

### 2.1 Templates to Add or Verify Exist

**LSASS access (Sysmon Event ID 10):**

The normalizer must detect when `TargetImage` contains `lsass.exe` and set
`event_type = PRIVILEGE_ESCALATION`. The template:

```
"{process_name} on {hostname} accessed process lsass.exe (PID {dest_port}) —
credential dumping attempt. Access mask indicates memory read."
```

Map `TargetPid` to a custom field and include it. If the field is missing,
substitute "unknown PID".

**Registry modification (Sysmon Event ID 13):**

```
"{process_name} on {hostname} modified registry key {registry_key} to value
{command_line_args} — possible persistence or defense evasion."
```

If `registry_key` contains `Run` or `RunOnce`: append "Registry run key
persistence detected." and set `mitre_technique_hint = T1547.001`.
If it contains `DisableAntiSpyware` or `DisableRealtimeMonitoring`: append
"Antivirus disabled via registry." and set `mitre_technique_hint = T1562.001`.

**Service install (Windows Event ID 7045):**

```
"New service '{command_line_args}' installed on {hostname} with path
{file_path} running as {user_account} — possible persistence mechanism."
```

Use `ServiceName` → `command_line_args`, `ImagePath` → `file_path`.
Set `mitre_technique_hint = T1543.003`.

**Scheduled task creation (Windows Event ID 4698):**

```
"Scheduled task '{command_line_args}' created on {hostname} by {user_account}
— task will execute at logon/startup for persistence."
```

Set `mitre_technique_hint = T1053.005`.

**Log clearing (Windows Event ID 1102 / 104):**

```
"Security event log cleared on {hostname} by {user_account} — evidence
destruction in progress. This is a critical indicator of compromise."
```

This must classify as `EXFILTRATION_HINT` and score P0 immediately.

**Explicit credential use (Windows Event ID 4648):**

```
"User {user_account} on {hostname} authenticated to {dest_ip} using
explicit credentials — possible lateral movement with stolen credentials."
```

Set `mitre_technique_hint = T1021`.

**Shadow copy deletion:**

Add to the `PROCESS_CREATION` enrichment rules:
If `command_line_args` contains `vssadmin` and `delete`: append "Shadow copies
deleted — ransomware preparation or anti-forensics." and set
`mitre_technique_hint = T1490`. Score this P0.
If `command_line_args` contains `wevtutil` and `cl`: append "Event log cleared
via wevtutil." Set `mitre_technique_hint = T1070.001`. Score P0.
If `command_line_args` contains `bcdedit` and `recoveryenabled No`: append
"Boot recovery disabled." Set `mitre_technique_hint = T1490`.

**C2 port enrichment:**

Extend the C2 port list in `threat_lists.yaml`:
```yaml
c2_ports:
  - 4444
  - 5555
  - 1337
  - 8888
  - 9001
  - 8443   # ADD THIS — used in scenario
  - 4443   # ADD THIS
  - 2222   # ADD THIS
```

**Known C2 IPs list (add to threat_lists.yaml):**
```yaml
known_c2_ips:
  - "185.220.101.45"
  - "185.220.101.46"
  - "91.92.248.55"
  - "203.0.113.77"
```

Add a check in the Triage SKILL: if `source_ip` or `dest_ip` is in `known_c2_ips`,
add +50 to severity score and flag as `known_c2_ip`. This is a new flag condition
not in the original implementation.

---

## 3. Triage Scorer Additions

The current triage scorer in `triage_scorer.py` covers five flag conditions.
The scenario exercises additional patterns. Add these before the test run.

### 3.1 New Flag Conditions

**Flag: LSASS access** (+50 points)
```
Condition: event_type == PRIVILEGE_ESCALATION AND "lsass" in command_line_args.lower()
Score contribution: +50
Flag label: "lsass_access"
```

**Flag: Encoded PowerShell command** (+35 points)
```
Condition: process_name contains "powershell" AND command_line_args contains "-enc"
  OR command_line_args contains "-EncodedCommand"
Score contribution: +35
Flag label: "encoded_powershell"
```

**Flag: Log clearing** (+60 points → always P0)
```
Condition: event_type == EXFILTRATION_HINT AND (
  "wevtutil" in process_name.lower() OR
  event_code in [1102, 104]
)
Score contribution: +60
Flag label: "log_clearing"
```

**Flag: Shadow copy deletion** (+60 points → always P0)
```
Condition: "vssadmin" in command_line_args.lower() AND "delete" in command_line_args.lower()
Score contribution: +60
Flag label: "shadow_delete"
```

**Flag: Known bad process hash** (+45 points)
```
Condition: "Hashes" field present AND known_bad_hashes list contains the SHA256
Score contribution: +45
Flag label: "known_bad_hash"
```
Add to threat_lists.yaml:
```yaml
known_bad_hashes:
  - "61C0810A23580CF492A6BA4F7654566108331E7A4134C968C2D6A05261B2D8A1"
```
This is the mimikatz hash in the scenario.

**Flag: Large data transfer** (+40 points)
```
Condition: (orig_bytes or bytes_sent field) > 10485760 (10MB)
Score contribution: +40
Flag label: "large_data_transfer"
```

**Flag: Port scan pattern** (+30 points)
```
Condition: Same source_ip appears in 15+ DENY firewall entries within the
  ingestion buffer within 90 seconds
Score contribution: +30 (applied to the batch, not individual entries)
Flag label: "port_scan_detected"
```
This requires state tracking across entries — store a rolling counter in
Cognitive RAM keyed by `activity:portscan:{src_ip}:{minute_bucket}`.

---

## 4. Expected Alert Sequence

When you run the scenario log through the pipeline, this is the sequence of
alerts the system should produce. Use this as your verification checklist.

### Pre-Alert (immediate, before correlation):
1. **T+630** — P1 alert: "web shell execution" (apache httpd spawning cmd.exe)
2. **T+800** — P1 alert: "encoded PowerShell" (powershell -enc from cmd.exe)
3. **T+1100** — P0 alert: "dangerous process mimikatz" (m64.exe with credential flags)
4. **T+1110** — P0 alert: "LSASS memory access" (Sysmon Event 10)
5. **T+3600** — P0 alert: "shadow copy deletion" (vssadmin delete shadows)
6. **T+3700** — P0 alert: "ransomware binary" (crypt0r.exe)
7. **T+3900** — P0 alert: "log clearing" (Event ID 1102)

### Full Forensic Reports (after correlation — should reference historical cluster):
1. **Phase 2 report** — Correlates web shell file write + cmd.exe spawn + ipconfig/systeminfo
   → Narrative: "Web shell uploaded and executed on WEBSERVER01"
   → MITRE: T1505.003 (Web Shell), T1059.003 (CMD)

2. **Phase 3 report** — Correlates PowerShell + network connection + file drop
   → Narrative: "PowerShell retrieved and executed payload from C2"
   → MITRE: T1059.001 (PowerShell), T1105 (Ingress Tool Transfer), T1055 (Process Injection)

3. **Phase 4 report** — Correlates mimikatz + LSASS access + procdump + reg save
   → Narrative: "Credential dumping via multiple methods on WEBSERVER01"
   → MITRE: T1003.001 (LSASS Memory), T1003.002 (SAM)

4. **Phase 5 report** — Correlates SMB scan + pass-the-hash logons + WMI execution + psexec
   → Narrative: "Lateral movement to FILESERVER01 and DBSERVER01 using stolen credentials"
   → MITRE: T1021.002 (SMB), T1021.006 (WMI), T1570 (Lateral Tool Transfer)

5. **Phase 7 report** — Correlates DNS queries with high-entropy subdomains
   → Narrative: "DNS tunneling detected — base64-encoded data exfiltrated via DNS TXT queries"
   → MITRE: T1071.004 (DNS)

6. **Phase 9 report** — Correlates curl + large conn + HTTP POST
   → Narrative: "100MB data exfiltrated to 185.220.101.45 via HTTPS"
   → MITRE: T1041 (Exfiltration over C2 Channel)

7. **Phase 10-11 report** — Correlates shadow delete + encryption binary + log clearing
   → Narrative: "Ransomware preparation: backups destroyed, encryption started, logs cleared"
   → MITRE: T1490 (Inhibit System Recovery), T1486 (Data Encrypted for Impact), T1070

---

## 5. Knowledge Graph — Expected Nodes and Edges

After the full scenario runs, the Cytoscape.js graph should contain:

### Nodes (at minimum):
| Entity | Type | Expected threat_score | Color |
|--------|------|----------------------|-------|
| WEBSERVER01 | hostname | >60 | red |
| FILESERVER01 | hostname | >60 | red |
| DBSERVER01 | hostname | 40–60 | amber |
| DC01 | hostname | 30–40 | amber |
| 203.0.113.77 | ip | >60 | red |
| 185.220.101.45 | ip | >60 | red |
| 185.220.101.46 | ip | >60 | red |
| 10.10.2.10 | ip | >60 | red |
| NT AUTHORITY\SYSTEM | user | >60 | red |
| NETWORK SERVICE | user | 40–60 | amber |
| Administrator | user | >60 | red |
| m64.exe | process | >60 | red |
| mimikatz / m64.exe | process | >60 | red |
| powershell.exe | process | >60 | red |
| cmd.exe | process | 40–60 | amber |
| crypt0r.exe | process | >60 | red |
| svc_patch.exe | process | >60 | red |
| lsass.dmp | file | >60 | red |

### Edges (key ones to verify):
- `203.0.113.77` → `WEBSERVER01` (type: network_scan, technique: T1046)
- `WEBSERVER01/httpd.exe` → `WEBSERVER01/cmd.exe` (type: process_spawn, T1505.003)
- `WEBSERVER01` → `185.220.101.45` (type: c2_beacon, T1071)
- `WEBSERVER01/m64.exe` → `lsass.exe` (type: credential_access, T1003.001)
- `WEBSERVER01` → `FILESERVER01` (type: lateral_movement, T1021.002)
- `WEBSERVER01` → `DBSERVER01` (type: lateral_movement, T1021.002)
- `WEBSERVER01` → `185.220.101.45:8443` (type: exfiltration, T1041)
- `FILESERVER01/crypt0r.exe` → `FILESERVER01` (type: ransomware, T1486)

---

## 6. How to Run the Test

Follow these steps exactly. Do not skip any.

### Step 1 — Pre-seed ChromaDB baseline

Run baseline generation first. Without this, every entry will be a cold-start
and no correlation will occur:

```bash
cd /path/to/aegis
python scripts/baseline_generator.py --count 500 --duration-hours 48
```

Wait for the script to complete. Confirm ChromaDB shows entries:
```bash
curl -s http://localhost:8003/stats | python -m json.tool
# Should show: "active_count": 500
```

Archive the seeded volume so you can restore it:
```bash
docker-compose stop chromadb
cp -r ./data/chromadb ./data/chromadb_baseline_backup
docker-compose start chromadb
```

### Step 2 — Verify all services are healthy

```bash
python scripts/diagnose.py
# All 24 checks must pass before proceeding
# Pay special attention to: device=cuda (not cpu) and correct embedding dim
```

### Step 3 — Open monitoring terminals

Open four terminal windows before injecting logs:

**Terminal 1 — Live log tail:**
```bash
tail -f logs/demo.log | python -m json.tool
```

**Terminal 2 — OpenClaw orchestrator output:**
```bash
cd openclaw && npm start 2>&1 | grep -E "(TRIAGE|CORRELATION|TIMELINE|ALERT|TELEGRAM|GRAPH)"
```

**Terminal 3 — Embedding service throughput:**
```bash
watch -n 2 "curl -s http://localhost:8001/stats | python -m json.tool"
```

**Terminal 4 — Knowledge graph (open in browser):**
```
http://localhost:5000
```

### Step 4 — Run the scenario injector

The scenario log is designed to be injected in phases with pauses between them
so the pipeline can process each phase before the next begins:

```bash
python scripts/scenario_injector.py \
  --log aegis_threat_scenario.log \
  --mode phased \
  --phase-pause 30 \
  --entry-delay 0.5
```

The `--entry-delay 0.5` adds 500ms between each log entry injection, giving
the embedding service time to process without saturating the queue on CPU hardware.
Reduce to 0.1 if running on GPU with CUDA.

If you do not have `scenario_injector.py`, use this approach manually:

```bash
# Inject one phase at a time — wait for Telegram alert before next phase
grep "^{" aegis_threat_scenario.log | head -60 >> logs/demo.log
sleep 30
grep "^{" aegis_threat_scenario.log | sed -n "61,110p" >> logs/demo.log
# and so on for each phase
```

### Step 5 — Verification checks after each phase

After Phase 2 (Initial Access) logs are injected, check:
```bash
curl -s http://localhost:8003/stats | python -m json.tool
# "active_count" should have increased — new logs embedded
curl -s http://localhost:5000/graph/stats | python -m json.tool
# WEBSERVER01 node should exist with threat_score > 0
```

After Phase 4 (Credential Dumping), check:
```bash
curl -s http://localhost:8000/queue/stats | python -m json.tool
# "p0_count" should be > 0 (mimikatz events)
# If p0_count is 0, the triage scorer is not flagging mimikatz — debug triage
```

---

## 7. Debugging Common Failures

### "No alerts received for Phase 2 web shell"

**Most likely cause:** The normalizer is not detecting `httpd.exe` as a web server parent.

**Fix:** In `intent_translator.py`, extend the web server parent list:
```python
WEB_SERVER_PARENTS = [
    "apache2.exe", "nginx.exe", "w3wp.exe", "tomcat.exe", "tomcat9.exe",
    "httpd.exe",          # ADD THIS — Apache on Windows uses httpd.exe
    "php-cgi.exe",        # ADD THIS
    "node.exe",           # ADD THIS — Node.js web servers
    "gunicorn",           # ADD THIS — Python
    "uvicorn",            # ADD THIS — FastAPI
]
```

### "DNS tunneling not flagged (Phase 7)"

**Most likely cause:** The Shannon entropy threshold is not being evaluated
against the full subdomain string including the encoded chunk.

**Fix:** In `intent_translator.py`, ensure entropy is computed on the full
query string before stripping the TLD, not just the final label. The tunnel
subdomains are 28+ characters of base64 — computing entropy on just one
label segment will correctly return >3.5. But if the code strips at the
first dot, it may only evaluate the TLD. Test with:
```python
from ingestion.intent_translator import compute_entropy
print(compute_entropy("c29tZXNlY3JldGRhdGFjaHVuazE"))  # Should be > 4.0
print(compute_entropy("google"))  # Should be < 3.0
```

### "Credential dumping (Phase 4) not generating P0"

**Most likely cause:** Sysmon Event ID 10 (process access) is not being
handled by the normalizer — it falls through to UNKNOWN event type, which
scores low.

**Fix:** Add explicit Event ID 10 handling in `normalizer.py`:
```python
elif event_id == 10:
    entry["event_type"] = "PRIVILEGE_ESCALATION"
    entry["process_name"] = fields.get("SourceImage", "unknown").split("\\")[-1]
    entry["dest_ip"] = fields.get("TargetImage", "unknown")  # store target process
    entry["command_line_args"] = f"GrantedAccess:{fields.get('GrantedAccess','?')} Target:{fields.get('TargetImage','?')}"
```

### "Log clearing events (Phase 11) not generating P0"

**Most likely cause:** Windows Event ID 1102 and 104 are not in the
normalizer's Windows Event handler, falling through to UNKNOWN.

**Fix:** Add explicit handling:
```python
elif event_id in [1102, 104]:
    entry["event_type"] = "EXFILTRATION_HINT"
    entry["process_name"] = "wevtutil.exe"  # implied
    entry["user_account"] = fields.get("SubjectUserName", "unknown")
    entry["command_line_args"] = f"EventLogCleared:Channel={fields.get('Channel','Security')}"
```

### "Knowledge graph shows fewer nodes than expected"

**Most likely cause:** Entity extraction in the graph service only pulls
`source_ip` and `dest_ip`, not `process_name`, `user_account`, or `hostname`
from the forensic report's `entities` field.

**Fix:** In `graph_service.py`, verify the `/graph/ingest` endpoint processes
all entity types from the `ForensicReport.entities` list. The report schema
defines `EntityNode` with a `type` field — ensure all types (ip, hostname,
process, user, file) create graph nodes.

---

## 8. MITRE ATT&CK Coverage — Extend the Reference Table

The current Timeline SKILL.md system prompt includes 10 technique IDs.
The scenario exercises 6 additional techniques. Add these to the Qwen 2.5
system prompt reference table before the test run:

```
Current (already in system prompt):
T1059 — Command and Scripting Interpreter
T1021 — Remote Services
T1055 — Process Injection
T1071 — Application Layer Protocol
T1486 — Data Encrypted for Impact
T1003 — OS Credential Dumping
T1105 — Ingress Tool Transfer
T1543 — Create or Modify System Process
T1505 — Server Software Component
T1190 — Exploit Public-Facing Application

ADD THESE for scenario coverage:
T1046 — Network Service Discovery (port scan)
T1053 — Scheduled Task/Job (schtasks persistence)
T1547 — Boot or Logon Autostart Execution (registry Run key)
T1490 — Inhibit System Recovery (vssadmin, bcdedit)
T1070 — Indicator Removal (wevtutil, log clearing)
T1562 — Impair Defenses (Defender registry disable)
T1041 — Exfiltration Over C2 Channel (curl upload)
T1048 — Exfiltration Over Alternative Protocol (FTP attempt)
```

Update `services/orchestrator/synthesizer.py` in the section where the
system prompt is constructed. The MITRE reference table is a Python string —
append the new entries to the same format as the existing ones.

---

## 9. Expected Test Outcome Summary

| Metric | Expected Value | How to Verify |
|--------|---------------|---------------|
| Total log entries ingested | 202 | `curl localhost:8000/queue/stats` |
| Entries reaching ChromaDB | ~150 (excludes BENIGN) | `curl localhost:8003/stats` |
| P0 alerts fired | 7–9 | OpenClaw logs `[ALERT] P0` count |
| P1 alerts fired | 4–6 | OpenClaw logs `[ALERT] P1` count |
| BENIGN entries (not queued) | ~50 | Baseline phase logs |
| Forensic reports generated | 6–8 | Telegram messages received |
| Knowledge graph nodes | 18–25 | `localhost:5000` node count |
| Knowledge graph edges | 12–18 | `localhost:5000` edge count |
| Avg report confidence | > 0.55 | Telegram messages — confidence field |
| ATT&CK IDs correctly mapped | > 12 unique IDs across all reports | Count unique IDs in reports |
| DLQ entries (failures) | 0 (target) | `curl localhost:8000/dlq/stats` |

If DLQ count > 0 after the test, inspect with:
```bash
sqlite3 data/aegis.db "SELECT work_type, failure_reason, retry_count FROM dead_letter_queue;"
```

---

*This document should be read alongside the implementation methodology.
All section references (§1.x, §2.x etc.) point to the AEGIS Implementation
Methodology document.*
