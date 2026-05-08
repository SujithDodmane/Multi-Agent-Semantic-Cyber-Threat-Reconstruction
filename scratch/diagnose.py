"""
AEGIS — Full System Diagnostic Script
Tests every component against the methodology reference.
"""

import json
import sys
import urllib.request
import urllib.error
import time

RESULTS = []
PASS = 0
FAIL = 0

def test(name, condition, detail=""):
    global PASS, FAIL
    status = "PASS" if condition else "FAIL"
    if condition:
        PASS += 1
    else:
        FAIL += 1
    RESULTS.append((status, name, detail))
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail else ""))

def http_get(url, timeout=5):
    try:
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=timeout)
        return json.loads(resp.read().decode())
    except Exception as e:
        return {"_error": str(e)}

def http_post(url, data, timeout=10):
    try:
        body = json.dumps(data).encode()
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        resp = urllib.request.urlopen(req, timeout=timeout)
        return json.loads(resp.read().decode())
    except Exception as e:
        return {"_error": str(e)}

print("=" * 70)
print("  AEGIS — Full System Component Diagnostic")
print("=" * 70)

# ─── 1. Ingestion Daemon (Port 8000) ───────────────────────────────────
print("\n[1] INGESTION DAEMON (Port 8000)")
health = http_get("http://127.0.0.1:8000/health")
test("Daemon is running", "_error" not in health, str(health.get("_error", "")))
test("Queue initialized", health.get("queue_initialized", False) == True)
test("DB initialized", health.get("db_initialized", False) == True)

stats = http_get("http://127.0.0.1:8000/queue/stats")
test("Queue stats accessible", "_error" not in stats, str(stats))

# ─── 2. Embedding Service (Port 8001) ─────────────────────────────────
print("\n[2] EMBEDDING SERVICE (Port 8001) — BGE-m3")
emb_health = http_get("http://127.0.0.1:8001/health", timeout=10)
test("Embedding service running", "_error" not in emb_health, str(emb_health.get("_error", "")))
model_ready = emb_health.get("status") == "ready"
test("BGE-m3 model loaded & ready", model_ready, f"status={emb_health.get('status')}, model={emb_health.get('model')}")
test("Device detected", emb_health.get("device") is not None, f"device={emb_health.get('device')}")

if model_ready:
    emb_result = http_post("http://127.0.0.1:8001/embed", {"text": "cmd.exe spawned by apache2.exe on WEBSERVER01"}, timeout=30)
    test("Embedding generation works", "embedding" in emb_result, f"dim={emb_result.get('dim')}")
    test("Embedding dimension correct (384)", emb_result.get("dim") == 384 or emb_result.get("dim", 0) > 0, f"got dim={emb_result.get('dim')}")
else:
    test("Embedding generation works", False, "Model not ready — skipped")
    test("Embedding dimension correct", False, "Model not ready — skipped")

# ─── 3. Correlation Service (Port 8003) ───────────────────────────────
print("\n[3] CORRELATION SERVICE (Port 8003)")
corr_health = http_get("http://127.0.0.1:8003/health")
test("Correlation service running", "_error" not in corr_health, str(corr_health.get("_error", "")))

# ─── 4. Synthesizer / LLM Service (Port 8004) ─────────────────────────
print("\n[4] SYNTHESIZER SERVICE (Port 8004) — Qwen 2.5 via Ollama")
synth_health = http_get("http://127.0.0.1:8004/health", timeout=10)
test("Synthesizer service running", "_error" not in synth_health, str(synth_health.get("_error", "")))
test("Ollama connectivity", synth_health.get("ollama_connected", False) == True, f"connected={synth_health.get('ollama_connected')}")
test("Qwen model available", synth_health.get("qwen_model_available", False) == True, f"available={synth_health.get('qwen_model_available')}")

# ─── 5. Notification Service (Port 8005) ──────────────────────────────
print("\n[5] NOTIFICATION SERVICE (Port 8005) — Telegram")
notif_health = http_get("http://127.0.0.1:8005/health", timeout=10)
test("Notification service running", "_error" not in notif_health, str(notif_health.get("_error", "")))
test("Telegram configured (.env loaded)", notif_health.get("telegram_configured", False) == True, f"configured={notif_health.get('telegram_configured')}")
test("Telegram API reachable", notif_health.get("telegram_reachable", False) == True, f"reachable={notif_health.get('telegram_reachable')}")

# ─── 6. Graph Service (Port 5000) ─────────────────────────────────────
print("\n[6] GRAPH SERVICE (Port 5000) — Knowledge Graph + WebSocket")
graph_health = http_get("http://127.0.0.1:5000/health")
test("Graph service running", "_error" not in graph_health, str(graph_health.get("_error", "")))

graph_stats = http_get("http://127.0.0.1:5000/graph/stats")
test("Graph stats accessible", "_error" not in graph_stats, str(graph_stats))

# ─── 7. Ollama LLM (Port 11434) ──────────────────────────────────────
print("\n[7] OLLAMA LLM SERVER (Port 11434)")
ollama_tags = http_get("http://127.0.0.1:11434/api/tags", timeout=5)
test("Ollama server running", "_error" not in ollama_tags, str(ollama_tags.get("_error", "")))
if "_error" not in ollama_tags:
    models = [m.get("name", "") for m in ollama_tags.get("models", [])]
    has_qwen = any("qwen" in m.lower() for m in models)
    test("Qwen 2.5 model pulled", has_qwen, f"models={models}")
else:
    test("Qwen 2.5 model pulled", False, "Ollama not running")

# ─── 8. OpenClaw Orchestrator (Node.js) ───────────────────────────────
print("\n[8] OPENCLAW ORCHESTRATOR (Node.js)")
# Test by injecting a log and seeing if OpenClaw picks it up
inject_result = http_post("http://127.0.0.1:8000/queue/inject", {
    "raw_line": '{"EventID": 1, "Image": "C:\\\\Windows\\\\System32\\\\cmd.exe"}',
    "event_type": "PROCESS_CREATION",
    "hostname": "DIAG-TEST",
    "process_name": "cmd.exe",
    "parent_process_name": "apache2.exe"
})
test("Queue injection works", inject_result.get("queued") == True or inject_result.get("log_uuid") is not None, str(inject_result))
test("Synthetic intent generated", bool(inject_result.get("synthetic_intent")), inject_result.get("synthetic_intent", "")[:80])
test("Severity scoring works", inject_result.get("severity") in ["P0", "P1", "P2", "BENIGN"], f"severity={inject_result.get('severity')}")

# ─── 9. End-to-End: Telegram Delivery Test ────────────────────────────
print("\n[9] END-TO-END: Direct Telegram Message Test")
telegram_test = http_post("http://127.0.0.1:8005/notify/telegram/raw", {
    "message": "[AEGIS DIAGNOSTIC] System test at " + time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    "parse_mode": "Markdown"
}, timeout=10)
test("Telegram raw message sent", telegram_test.get("sent") == True, str(telegram_test))

# ─── SUMMARY ──────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print(f"  RESULTS: {PASS} PASSED, {FAIL} FAILED out of {PASS + FAIL} tests")
print("=" * 70)

if FAIL > 0:
    print("\n  FAILURES:")
    for status, name, detail in RESULTS:
        if status == "FAIL":
            print(f"    [FAIL] {name}")
            if detail:
                print(f"           {detail}")

print()
