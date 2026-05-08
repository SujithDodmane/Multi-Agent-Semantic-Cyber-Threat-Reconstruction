import sys
import io

# Force UTF-8 for Windows console
if sys.platform == "win32":
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', line_buffering=True)
        sys.stderr.reconfigure(encoding='utf-8', line_buffering=True)

import time
import os
import subprocess
import threading
import signal
import json

# ANSI Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

SERVICES = [
    {"name": "INGESTION", "cmd": ["claw\\Scripts\\python.exe", "-m", "ingestion.daemon"], "port": 8000},
    {"name": "EMBEDDING", "cmd": ["claw\\Scripts\\uvicorn.exe", "services.embedding.app:app", "--host", "127.0.0.1", "--port", "8001"], "port": 8001},
    {"name": "CORRELATION", "cmd": ["claw\\Scripts\\uvicorn.exe", "services.correlation.app:app", "--host", "127.0.0.1", "--port", "8003"], "port": 8003},
    {"name": "SYNTHESIZER", "cmd": ["claw\\Scripts\\uvicorn.exe", "services.orchestrator.synthesizer:app", "--host", "127.0.0.1", "--port", "8004"], "port": 8004},
    {"name": "NOTIFICATION", "cmd": ["claw\\Scripts\\uvicorn.exe", "services.notification.telegram_bot:app", "--host", "127.0.0.1", "--port", "8005"], "port": 8005},
    {"name": "GRAPH_VIZ", "cmd": ["claw\\Scripts\\uvicorn.exe", "services.graph.graph_service:app", "--host", "127.0.0.1", "--port", "5000"], "port": 5000},
]

OPENCLAW_CMD = ["npm", "start"]
OPENCLAW_CWD = "openclaw"

processes = []

def log(service, msg):
    color = CYAN
    if "[ALERT]" in msg or "P0" in msg or "🔴" in msg: color = RED
    elif "[TRIAGE]" in msg or "🟡" in msg: color = YELLOW
    elif "[CORRELATION]" in msg or "🟢" in msg: color = GREEN
    
    # Prettify the output
    msg = msg.replace("[AEGIS]", "🛡 AEGIS")
    msg = msg.replace("[TRIAGE]", "🔍 TRIAGE")
    msg = msg.replace("[STORAGE]", "💾 STORAGE")
    msg = msg.replace("[CORRELATION]", "🔗 CORRELATION")
    msg = msg.replace("[SYNTHESIZER]", "🧠 SYNTHESIZER")
    msg = msg.replace("[ALERT]", "⚠️ ALERT")
    
    print(f"{BOLD}[{service}]{RESET} {color}{msg}{RESET}")

def stream_output(service_name, pipe):
    for line in iter(pipe.readline, ''):
        line = line.strip()
        if line:
            # Filter some noise
            if "GET /health" in line or "200 OK" in line: continue
            if "INFO: " in line and "uvicorn" in line.lower(): continue
            log(service_name, line)

def signal_handler(sig, frame):
    print(f"\n{RED}Stopping all services...{RESET}")
    for p in processes:
        try:
            p.terminate()
        except:
            pass
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def main():
    print(f"{BOLD}{CYAN}==================================================={RESET}")
    print(f"{BOLD}{CYAN}       AEGIS MISSION CONTROL — DEMO SUITE          {RESET}")
    print(f"{BOLD}{CYAN}==================================================={RESET}")
    
    # 1. Start Python Services
    for svc in SERVICES:
        print(f"{GREEN}Launching {svc['name']}...{RESET}")
        p = subprocess.Popen(
            svc['cmd'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            bufsize=1,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        )
        processes.append(p)
        threading.Thread(target=stream_output, args=(svc['name'], p.stdout), daemon=True).start()
        time.sleep(1)

    # 2. Start OpenClaw
    print(f"{GREEN}Launching OPENCLAW ORCHESTRATOR...{RESET}")
    p_claw = subprocess.Popen(
        OPENCLAW_CMD,
        cwd=OPENCLAW_CWD,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        bufsize=1,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    )
    processes.append(p_claw)
    threading.Thread(target=stream_output, args=("ORCHESTRATOR", p_claw.stdout), daemon=True).start()

    print(f"\n{BOLD}{YELLOW}System Warmup Complete. Press Ctrl+C to stop.{RESET}")
    print(f"{BOLD}{YELLOW}Run 'python scripts/scenario_injector.py' to start log injection.{RESET}\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)

if __name__ == "__main__":
    main()
