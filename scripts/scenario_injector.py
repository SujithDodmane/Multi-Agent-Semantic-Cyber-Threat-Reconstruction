import time
import json
import os
import sys
import io

# Force UTF-8 for Windows console
if sys.platform == "win32":
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', line_buffering=True)
        sys.stderr.reconfigure(encoding='utf-8', line_buffering=True)
from pathlib import Path

# ANSI Colors
CYAN = "\033[96m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"

SCENARIO_FILE = "tests/aegis_threat_scenario.log"
OUTPUT_DIR = "logs"
OUTPUT_FILE = "logs/scenario.log"

def inject():
    if not os.path.exists(SCENARIO_FILE):
        print(f"[ERROR] Scenario file {SCENARIO_FILE} not found.")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Clear existing log file
    with open(OUTPUT_FILE, "w") as f:
        pass

    print(f"\n🚀 {BOLD}{CYAN}--- AEGIS SCENARIO INJECTION START ---{RESET}")
    print(f"📄 Source: {SCENARIO_FILE}")
    
    with open(SCENARIO_FILE, "r") as f:
        lines = f.readlines()

    current_phase = ""
    batch = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        if line.startswith("# === PHASE"):
            # If we have a pending batch, inject it before starting new phase
            if batch:
                process_batch(batch, current_phase)
                batch = []
            
            current_phase = line.split("===")[1].strip()
            print(f"\n⚡ {BOLD}{YELLOW}[PHASE] {current_phase}{RESET}")
            time.sleep(3) # Pause for demo clarity
            continue
            
        if line.startswith("#"):
            continue # Skip other comments
            
        try:
            # Validate JSON
            json.loads(line)
            batch.append(line)
        except:
            continue

    # Final batch
    if batch:
        process_batch(batch, current_phase)

    print("\n--- Injection Complete ---")

def process_batch(batch, phase_name):
    # Reduce load: If it's a large batch of benign logs, sample them
    if "BENIGN" in phase_name.upper() and len(batch) > 10:
        batch = batch[::3] # Take every 3rd benign log
        print(f" 🧪 Sampling benign batch (Reduced to {len(batch)} logs)")

    print(f" 📥 Ingesting {len(batch)} logs into pipeline...")
    with open(OUTPUT_FILE, "a") as f:
        for line in batch:
            f.write(line + "\n")
            f.flush()
            time.sleep(0.8) # Increased delay significantly to reduce RAM pressure
    time.sleep(5) # Wait longer for processing

if __name__ == "__main__":
    inject()
