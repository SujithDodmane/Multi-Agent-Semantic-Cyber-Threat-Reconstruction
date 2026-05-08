"""
AEGIS — Full End-to-End Attack Simulation
Injects a P0 critical event (mimikatz) and monitors the full agent chain.
"""
import json
import time
import urllib.request

def http_post(url, data, timeout=10):
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=timeout)
    return json.loads(resp.read().decode())

def http_get(url, timeout=10):
    resp = urllib.request.urlopen(url, timeout=timeout)
    return json.loads(resp.read().decode())

print("=" * 60)
print("  AEGIS — Full End-to-End Attack Chain Test")
print("=" * 60)

# Step 1: Inject P0 - Mimikatz credential dumping
print("\n[STEP 1] Injecting P0: mimikatz.exe credential dump...")
r1 = http_post("http://127.0.0.1:8000/queue/inject", {
    "raw_line": '{"EventID": 10, "Image": "C:\\\\Windows\\\\Temp\\\\mimikatz.exe", "TargetImage": "C:\\\\Windows\\\\System32\\\\lsass.exe"}',
    "event_type": "PRIVILEGE_ESCALATION",
    "hostname": "WEBSERVER01",
    "process_name": "mimikatz.exe",
    "parent_process_name": "cmd.exe",
    "source_ip": "10.0.0.50",
    "user_account": "www-data",
    "command_line_args": "mimikatz.exe sekurlsa::logonpasswords"
})
print(f"  UUID: {r1['log_uuid']}")
print(f"  Severity: {r1['severity']}")
print(f"  Intent: {r1['synthetic_intent'][:100]}")
print(f"  Queued: {r1['queued']}")

# Step 2: Inject network recon
print("\n[STEP 2] Injecting P2: Network reconnaissance on SMB port 445...")
r2 = http_post("http://127.0.0.1:8000/queue/inject", {
    "raw_line": '{"EventID": 3, "Image": "C:\\\\Windows\\\\System32\\\\cmd.exe"}',
    "event_type": "NETWORK_CONNECTION",
    "hostname": "WEBSERVER01",
    "process_name": "cmd.exe",
    "source_ip": "10.0.0.50",
    "dest_ip": "10.0.0.100",
    "dest_port": 445,
    "user_account": "www-data"
})
print(f"  UUID: {r2['log_uuid']}")
print(f"  Severity: {r2['severity']}")
print(f"  Intent: {r2['synthetic_intent'][:100]}")

# Step 3: Inject lateral movement
print("\n[STEP 3] Injecting: Lateral movement via SMB...")
r3 = http_post("http://127.0.0.1:8000/queue/inject", {
    "raw_line": '{"EventID": 4624, "LogonType": 3}',
    "event_type": "LATERAL_MOVEMENT_HINT",
    "hostname": "DBSERVER02",
    "source_ip": "10.0.0.50",
    "dest_ip": "10.0.0.100",
    "dest_port": 445,
    "user_account": "Administrator",
    "process_name": "svchost.exe"
})
print(f"  UUID: {r3['log_uuid']}")
print(f"  Severity: {r3['severity']}")
print(f"  Intent: {r3['synthetic_intent'][:100]}")

# Wait for OpenClaw to process all through the agent chain
print("\n[WAITING] Giving OpenClaw + Qwen 2.5 time to process (up to 120 seconds)...")
for i in range(24):
    time.sleep(5)
    stats = http_get("http://127.0.0.1:8000/queue/stats")
    graph = http_get("http://127.0.0.1:5000/graph/stats")
    print(f"  [{(i+1)*5}s] Queue depth: {stats['depth']} | Graph: {graph['total_nodes']} nodes, {graph['total_edges']} edges")
    if stats['depth'] == 0 and graph['total_nodes'] > 2:
        print("  Pipeline drained + graph updated!")
        break

# Final verification
print("\n[VERIFICATION]")
graph_full = http_get("http://127.0.0.1:5000/graph/full")
nodes = graph_full.get("elements", {}).get("nodes", [])
edges = graph_full.get("elements", {}).get("edges", [])
print(f"  Graph nodes: {len(nodes)}")
for n in nodes:
    d = n.get("data", {})
    print(f"    - {d.get('type','?')}: {d.get('label','?')} (threat_score={d.get('threat_score','?')})")
print(f"  Graph edges: {len(edges)}")
for e in edges:
    d = e.get("data", {})
    print(f"    - {d.get('source','?')} --[{d.get('label','?')}]--> {d.get('target','?')}")

print("\n[DONE] Check your Telegram chat and http://localhost:5000 for the graph!")
