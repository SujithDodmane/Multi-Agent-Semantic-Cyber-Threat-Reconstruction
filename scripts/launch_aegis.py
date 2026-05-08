import os
import subprocess
import time
import sys
import threading
import signal
import socket

# Configuration
VENV_PYTHON = os.path.join("claw", "Scripts", "python.exe")
VENV_UVICORN = os.path.join("claw", "Scripts", "uvicorn.exe")

SERVICES = [
    {"name": "INGESTION", "cmd": [VENV_PYTHON, "-m", "ingestion.daemon"], "port": 8000},
    {"name": "EMBEDDING", "cmd": [VENV_UVICORN, "services.embedding.app:app", "--host", "127.0.0.1", "--port", "8001"], "port": 8001},
    {"name": "CORRELATION", "cmd": [VENV_UVICORN, "services.correlation.app:app", "--host", "127.0.0.1", "--port", "8003"], "port": 8003},
    {"name": "SYNTHESIZER", "cmd": [VENV_UVICORN, "services.orchestrator.synthesizer:app", "--host", "127.0.0.1", "--port", "8004"], "port": 8004},
    {"name": "NOTIFICATION", "cmd": [VENV_UVICORN, "services.notification.telegram_bot:app", "--host", "127.0.0.1", "--port", "8005"], "port": 8005},
    {"name": "GRAPH_VIZ", "cmd": [VENV_UVICORN, "services.graph.graph_service:app", "--host", "127.0.0.1", "--port", "5000"], "port": 5000},
]

processes = []

def check_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def start_ollama():
    if check_port(11434):
        print("[OK] Ollama is already running.")
        return
    
    print("[WAIT] Starting Ollama...")
    try:
        # Try to start ollama serve
        subprocess.Popen(["ollama", "serve"], creationflags=subprocess.CREATE_NEW_CONSOLE)
        time.sleep(5)
        if check_port(11434):
            print("[OK] Ollama started successfully.")
        else:
            print("[WARN] Ollama start command issued, but port 11434 is not responding yet.")
    except Exception as e:
        print(f"[ERROR] Failed to start Ollama: {e}. Please start it manually.")

def cleanup(sig, frame):
    print("\n[STOP] Stopping all AEGIS services...")
    for p in processes:
        p.terminate()
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)

def main():
    print("===================================================")
    print("   AEGIS MULTI-AGENT SYSTEM - MASTER LAUNCHER      ")
    print("===================================================")

    # 0. Start Ollama
    start_ollama()

    # 1. Start Python Services
    for svc in SERVICES:
        port = svc['port']
        if check_port(port):
            print(f"[WARN] Port {port} is in use. Forcefully clearing it...")
            try:
                # Find and kill process on this port (Windows)
                output = subprocess.check_output(f"netstat -ano | findstr :{port}", shell=True).decode()
                for line in output.splitlines():
                    if "LISTENING" in line:
                        pid = line.strip().split()[-1]
                        subprocess.run(f"taskkill /F /PID {pid} /T", shell=True, capture_output=True)
                time.sleep(1)
            except Exception as e:
                print(f"[ERROR] Failed to clear port {port}: {e}")
            
        print(f"[SVC] Starting {svc['name']} on port {port}...")
        # Use cmd /c title to set the window title
        full_cmd = ["cmd", "/c", "title", f"AEGIS - {svc['name']}", "&&"] + svc['cmd']
        p = subprocess.Popen(full_cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
        processes.append(p)
        time.sleep(1)

    # 2. Start OpenClaw
    print("[BRAIN] Starting OpenClaw Orchestrator...")
    os.chdir("openclaw")
    full_claw_cmd = ["cmd", "/c", "title", "AEGIS - OPENCLAW ORCHESTRATOR", "&&", "npm", "start"]
    p_claw = subprocess.Popen(full_claw_cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
    processes.append(p_claw)
    os.chdir("..")

    print("\n[DONE] All services launched in separate windows.")
    print("[INFO] Monitor the windows for logs.")
    print("[INFO] Press Ctrl+C in this window to stop all services.")
    
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
