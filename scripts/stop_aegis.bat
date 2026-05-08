@echo off
echo 🛑 Stopping AEGIS Multi-Agent System...
taskkill /F /IM python.exe /T 2>nul
taskkill /F /IM node.exe /T 2>nul
echo ✅ All services stopped.
pause
