import subprocess
import socket
import time
import sys

# AEGIS Service Ports
PORTS = [8000, 8001, 8003, 8004, 8005, 5000]

def check_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def kill_on_port(port):
    if not check_port(port):
        return False

    print(f"🛑 Terminating process on port {port}...")
    try:
        # Find PIDs listening on this port (Windows)
        output = subprocess.check_output(f"netstat -ano | findstr :{port}", shell=True).decode()
        pids = set()
        for line in output.splitlines():
            if "LISTENING" in line:
                parts = line.strip().split()
                if len(parts) > 4:
                    pids.add(parts[-1])
        
        for pid in pids:
            print(f"  > Killing PID {pid}")
            subprocess.run(f"taskkill /F /PID {pid} /T", shell=True, capture_output=True)
        return True
    except Exception as e:
        print(f"  > [ERROR] Failed to kill process on {port}: {e}")
        return False

def main():
    print("===================================================")
    print("   AEGIS SYSTEM — SURGICAL SHUTDOWN UTILITY        ")
    print("===================================================")
    
    found_any = False
    for port in PORTS:
        if kill_on_port(port):
            found_any = True
            time.sleep(0.5)
            
    # Also attempt to kill any remaining 'node' processes that might be hanging
    # (Optional: only if you want to be thorough)
    # subprocess.run("taskkill /F /IM node.exe /T", shell=True, capture_output=True)

    if not found_any:
        print("\n✅ No active AEGIS services found on designated ports.")
    else:
        print("\n✅ AEGIS shutdown complete.")

if __name__ == "__main__":
    main()
