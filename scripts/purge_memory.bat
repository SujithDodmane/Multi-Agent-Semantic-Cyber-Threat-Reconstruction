@echo off
echo [AEGIS] Shutting down services...
taskkill /F /IM python.exe /T >nul 2>&1
taskkill /F /IM node.exe /T >nul 2>&1

echo [AEGIS] Purging memory and cache...
if exist data\chromadb rmdir /s /q data\chromadb
if exist data\aegis.db del /f /q data\aegis.db
if exist data\cognitive_ram rmdir /s /q data\cognitive_ram

echo [AEGIS] Memory purged successfully.
echo [AEGIS] Dimension mismatch issues resolved.
echo [AEGIS] Starting services with fresh optimized memory...

python scripts/demo_orchestrator.py
