import urllib.request
import json
import uuid
import time

def test_ingestion():
    url = "http://localhost:8003/ingest"
    log_uuid = str(uuid.uuid4())
    data = {
        "synthetic_intent": "Attacker performed credential dumping using mimikatz",
        "log_uuid": log_uuid,
        "event_timestamp": time.time(),
        "event_type": "PROCESS_CREATION",
        "hostname": "WORKSTATION01",
        "user_account": "SYSTEM"
    }
    req = urllib.request.Request(url, data=json.dumps(data).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as response:
            res = json.loads(response.read().decode())
            print(f"[OK] Ingestion response: {res}")
            return res.get("success") == True
    except Exception as e:
        print(f"[FAIL] Ingestion test failed: {e}")
        return False

if __name__ == "__main__":
    test_ingestion()
