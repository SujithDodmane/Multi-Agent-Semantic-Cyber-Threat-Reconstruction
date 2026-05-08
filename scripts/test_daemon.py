import urllib.request
import json
import time

def test_daemon_flow():
    # 1. Inject raw log
    url_inject = "http://localhost:8000/queue/inject"
    raw_log = {
        "raw_line": "Jan 1 00:00:00 WORKSTATION01 Sysmon: EventID 1, Image C:\\Windows\\System32\\cmd.exe",
        "event_type": "PROCESS_CREATION",
        "hostname": "WORKSTATION01",
        "user_account": "jsmith",
        "synthetic_intent": "User jsmith executed cmd.exe on WORKSTATION01"
    }
    req_inject = urllib.request.Request(url_inject, data=json.dumps(raw_log).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req_inject) as resp:
            print(f"[OK] Log injected to daemon: {resp.status}")
    except Exception as e:
        print(f"[FAIL] Injection failed: {e}")
        return

    # 2. Check queue
    time.sleep(1)
    url_next = "http://localhost:8000/queue/next"
    try:
        with urllib.request.urlopen(url_next) as resp:
            res = json.loads(resp.read().decode())
            if res.get("found"):
                print(f"[OK] Log retrieved from queue: {res['entry']['log_uuid']}")
                print(f"[OK] Synthetic Intent: {res['entry']['synthetic_intent']}")
            else:
                print("[FAIL] Log not found in queue")
    except Exception as e:
        print(f"[FAIL] Queue poll failed: {e}")

if __name__ == "__main__":
    test_daemon_flow()
