import os
import requests
import sys
from dotenv import load_dotenv

load_dotenv()

SERVICES = {
    "Ingestion Daemon": os.getenv("INGESTION_API_URL", "http://localhost:8000") + "/health",
    "Embedding Service": os.getenv("EMBEDDING_SERVICE_URL", "http://localhost:8001") + "/health",
    "Correlation Service": os.getenv("CORRELATION_SERVICE_URL", "http://localhost:8003") + "/health",
    "Synthesizer Service": os.getenv("SYNTHESIZER_SERVICE_URL", "http://localhost:8004") + "/health",
    "Notification Service": os.getenv("NOTIFICATION_SERVICE_URL", "http://localhost:8005") + "/health",
    "Graph Service": os.getenv("GRAPH_SERVICE_URL", "http://localhost:5000") + "/health",
}

def check_health():
    print("--- AEGIS System Health Check ---")
    all_ok = True
    for name, url in SERVICES.items():
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                print(f"[OK] {name}: {resp.json().get('status', 'online')}")
            else:
                print(f"[ERR] {name}: Status {resp.status_code}")
                all_ok = False
        except Exception as e:
            print(f"[DOWN] {name}: {str(e)}")
            all_ok = False
    
    print("\n--- Environment Variables ---")
    required_vars = ["OPENCLAW_NODE_URL", "OLLAMA_BASE_URL", "CHROMA_PERSIST_DIRECTORY"]
    for var in required_vars:
        val = os.getenv(var)
        print(f"{var}: {'[SET]' if val else '[MISSING]'}")
        if not val:
            all_ok = False
            
    return all_ok

if __name__ == "__main__":
    if not check_health():
        sys.exit(1)
    sys.exit(0)
