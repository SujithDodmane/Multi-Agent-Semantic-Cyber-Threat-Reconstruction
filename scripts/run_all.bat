@echo off
echo ===================================================
echo AEGIS Demonstration Startup Script
echo ===================================================

REM Check for virtual environment
if not exist "claw\Scripts\python.exe" (
    echo [ERROR] Virtual environment 'claw' not found.
    pause
    exit /b 1
)

echo [1/6] Starting Ingestion Daemon (Port 8000)
start "AEGIS: Ingestion Daemon" cmd /c "claw\Scripts\python.exe -m ingestion.daemon"
timeout /t 2 > nul

echo [2/6] Starting Embedding Service (Port 8001)
start "AEGIS: Embedding Service" cmd /c "claw\Scripts\uvicorn.exe services.embedding.app:app --host 127.0.0.1 --port 8001"
timeout /t 2 > nul

echo [3/6] Starting Correlation Service (Port 8003)
start "AEGIS: Correlation Service" cmd /c "claw\Scripts\uvicorn.exe services.correlation.app:app --host 127.0.0.1 --port 8003"
timeout /t 2 > nul

echo [4/6] Starting Synthesizer LLM Service (Port 8004)
start "AEGIS: Synthesizer Service" cmd /c "claw\Scripts\uvicorn.exe services.orchestrator.synthesizer:app --host 127.0.0.1 --port 8004"
timeout /t 2 > nul

echo [5/6] Starting Notification Service (Port 8005)
start "AEGIS: Notification Service" cmd /c "claw\Scripts\uvicorn.exe services.notification.telegram_bot:app --host 127.0.0.1 --port 8005"
timeout /t 2 > nul

echo [6/6] Starting Knowledge Graph WebSocket (Port 5000)
start "AEGIS: Graph WebSocket" cmd /c "claw\Scripts\uvicorn.exe services.graph.graph_service:app --host 127.0.0.1 --port 5000"
timeout /t 2 > nul

echo.
echo ===================================================
echo Python Backend Services Started.
echo Starting OpenClaw Orchestrator (Node.js)
echo ===================================================
cd openclaw
start "AEGIS: OpenClaw Orchestrator" cmd /c "npm start"
cd ..

echo.
echo All services launched!
echo.
echo To run the demo, open a new terminal and run:
echo   python scripts/baseline_generator.py
echo   python scripts/demo_injector.py --scenario webshell
echo.
pause
