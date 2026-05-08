import json
import random
import time
import urllib.request

HOSTS = [f"WORKSTATION{i:02d}" for i in range(1, 20)] + ["WEBSERVER01", "DBSERVER01", "FILESERVER01"]
USERS = ["jsmith", "bwayne", "ckent", "dprince", "pparker", "SYSTEM", "NETWORK SERVICE"]

def inject_log(data):
    url = "http://localhost:8000/queue/inject"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as response:
            return response.status == 200
    except Exception as e:
        print(f"Error injecting: {e}")
        return False

print("[AEGIS] API-based Baseline Injector")
print("Injecting 500 benign logs...")

for i in range(500):
    host = random.choice(HOSTS)
    user = random.choice(USERS)
    
    # Randomly pick an event type
    etype = random.choice(["PROCESS_CREATION", "NETWORK_CONNECTION", "DNS_QUERY"])
    
    if etype == "PROCESS_CREATION":
        intent = f"User {user} executed a benign process on {host}."
    elif etype == "NETWORK_CONNECTION":
        intent = f"System process on {host} established a benign connection to a known update server."
    else:
        intent = f"Host {host} performed a standard DNS lookup for a common domain."

    payload = {
        "raw_line": f"Baseline log {i}",
        "event_type": etype,
        "hostname": host,
        "user_account": user,
        "synthetic_intent": intent
    }
    
    inject_log(payload)
    if (i+1) % 50 == 0:
        print(f"  Injected {i+1}/500...")

print("[OK] Baseline injection complete.")
