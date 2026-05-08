# Correlation SKILL — Semantic Vector Correlation

## Metadata
- **Name:** AEGIS Correlation Agent
- **Version:** 1.0.0
- **Description:** Finds semantically related log entries using BGE-m3 embeddings and ChromaDB vector search with temporal bounding.
- **RBAC Permissions:**
  - READ: Cognitive RAM (context namespace)
  - WRITE: Cognitive RAM (context namespace)
  - NETWORK: Python Correlation Service (`POST http://localhost:8003/correlate`)

## Input
1. Read handoff manifest from: `context:manifest:{log_uuid}`
   - Validate `schema_version` matches expected "1.0.0"
   - If mismatch: emit error to dead-letter queue, DO NOT proceed
2. Read `TriageOutput` + original `NormalizedLogEntry` from: `context:correlation:{log_uuid}`

## Logic

### Step 1: Validate Handoff Manifest
```
manifest = read("context:manifest:{log_uuid}")
if manifest.schema_version != "1.0.0":
    dead_letter_queue.add(log_uuid, "schema_version_mismatch")
    return  // DO NOT CRASH
```

### Step 2: Check Correlation Required
```
triage_output = read("context:correlation:{log_uuid}")
if !triage_output.correlation_required:
    // P2 or BENIGN — skip correlation, write minimal timeline context
    write("context:timeline:{log_uuid}", { cold_start: true, cluster_size: 0 })
    return
```

### Step 3: Call Python Correlation Service
HTTP POST to `http://localhost:8003/correlate`:
```json
{
  "synthetic_intent": "{entry.synthetic_intent}",
  "event_timestamp": 1715076000.0,
  "log_uuid": "{entry.log_uuid}",
  "event_type": "{entry.event_type}"
}
```

The Python service internally:
- Calls BGE-m3 embedding service → 384-dim vector
- Queries ChromaDB with temporal pre-filter (±2 hours)
- Applies cosine similarity threshold ≥0.72
- Returns top-k=20 correlated entries

### Step 4: Handle Response
- If `cold_start == true`: set flag, pass minimal context to Timeline
- If `cluster_size > 0`: pass full correlated cluster to Timeline
- If HTTP error: circuit breaker check, dead-letter queue

## Output
Write `CorrelationOutput` to Cognitive RAM key: `context:timeline:{log_uuid}`

```json
{
  "triggering_log": { "...NormalizedLogEntry..." },
  "correlation": {
    "correlated_entries": [
      {
        "log_uuid": "...",
        "synthetic_intent": "powershell.exe initiated connection to 10.0.0.5...",
        "cosine_similarity": 0.89,
        "event_timestamp": "2026-05-07T09:58:00Z"
      }
    ],
    "cluster_size": 5,
    "temporal_span_minutes": 45.2,
    "cold_start": false
  }
}
```

Also write handoff manifest to: `context:manifest:{log_uuid}`
```json
{
  "log_uuid": "...",
  "from_skill": "correlation",
  "schema_version": "1.0.0",
  "timestamp": "2026-05-07T10:00:05Z"
}
```

## Failure Handling
- **Embedding service down:** Circuit breaker OPEN → dead-letter queue + analyst notification
- **ChromaDB unavailable:** Same circuit breaker path
- **Schema version mismatch:** Dead-letter entry, explicit error, no crash
- **Empty results (cold start):** Gracefully pass cold_start=true to Timeline
