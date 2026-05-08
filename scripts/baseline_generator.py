"""
AEGIS — Baseline Generator

Generates synthetic benign logs to pre-seed the ChromaDB embeddings
and establish a "48-hour baseline" of normal activity.
This prevents the semantic correlation engine from operating in a
cold-start state during the demo.

Ref: Methodology §6.1 — Demo Environment Setup
"""

import json
import random
import time
import datetime
from pathlib import Path

# Common baseline artifacts
HOSTS = [f"WORKSTATION{i:02d}" for i in range(1, 20)] + ["WEBSERVER01", "DBSERVER01", "FILESERVER01"]
USERS = ["jsmith", "bwayne", "ckent", "dprince", "pparker", "SYSTEM", "NETWORK SERVICE"]
DOMAINS = ["google.com", "microsoft.com", "windowsupdate.com", "office365.com", "aws.amazon.com"]
IPS = [f"10.0.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(50)]

def generate_benign_sysmon_process() -> str:
    """Generate a benign Sysmon Event ID 1 (Process Creation)."""
    return json.dumps({
        "EventID": 1,
        "UtcTime": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
        "ProcessId": random.randint(1000, 9000),
        "Image": random.choice([
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "C:\\Windows\\explorer.exe",
            "C:\\Windows\\System32\\notepad.exe"
        ]),
        "CommandLine": "benign command execution",
        "User": f"CORP\\{random.choice(USERS)}",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "ParentProcessId": random.randint(1000, 9000),
        "Hashes": "SHA256=abcdef123456"
    })

def generate_benign_sysmon_network() -> str:
    """Generate a benign Sysmon Event ID 3 (Network Connection)."""
    return json.dumps({
        "EventID": 3,
        "UtcTime": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
        "ProcessId": random.randint(1000, 9000),
        "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "User": f"CORP\\{random.choice(USERS)}",
        "SourceIp": random.choice(IPS),
        "SourcePort": random.randint(50000, 65000),
        "DestinationIp": f"142.250.{random.randint(1,200)}.{random.randint(1,200)}",
        "DestinationPort": 443,
        "Protocol": "tcp"
    })

def generate_benign_zeek_dns() -> str:
    """Generate a benign Zeek DNS query."""
    return json.dumps({
        "ts": time.time(),
        "uid": f"C{random.randint(10000, 99999)}",
        "id.orig_h": random.choice(IPS),
        "id.orig_p": random.randint(50000, 65000),
        "id.resp_h": "8.8.8.8",
        "id.resp_p": 53,
        "query": random.choice(DOMAINS),
        "qtype": "A",
        "rcode": 0
    })

def main():
    print("\n[AEGIS] Baseline Generator")
    print("====================================")
    print("Generating synthetic 48-hour baseline logs...")
    
    log_dir = Path(__file__).resolve().parents[1] / "logs"
    log_dir.mkdir(exist_ok=True)
    
    baseline_file = log_dir / "baseline.log"
    
    entries_count = 500  # Adjust for demo purposes
    
    with open(baseline_file, "a") as f:
        for _ in range(entries_count):
            event_type = random.choice([
                generate_benign_sysmon_process,
                generate_benign_sysmon_network,
                generate_benign_zeek_dns
            ])
            
            f.write(event_type() + "\n")
            
            # Flush to disk so watchdog picks it up
            if random.random() < 0.1:
                f.flush()
                time.sleep(0.01)
                
    print(f"[OK] Generated {entries_count} baseline entries.")
    print(f"[DIR] Written to: {baseline_file}")
    print("\nThe Ingestion Daemon will now process these into ChromaDB.")
    print("Wait ~30 seconds for the queue to drain before running the demo.")

if __name__ == "__main__":
    main()
