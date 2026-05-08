# stop_aegis.ps1
# Script to forcefully terminate all AEGIS microservices and orchestrators

Write-Host "🛑 Stopping AEGIS Multi-Agent System..." -ForegroundColor Red

# Kill all Python processes (Backend services)
Write-Host "  > Terminating Python backend services..." -ForegroundColor Yellow
taskkill /F /IM python.exe /T 2>$null

# Kill all Node.js processes (OpenClaw Orchestrator)
Write-Host "  > Terminating Node.js orchestrator..." -ForegroundColor Yellow
taskkill /F /IM node.exe /T 2>$null

Write-Host "✅ All services stopped." -ForegroundColor Green
