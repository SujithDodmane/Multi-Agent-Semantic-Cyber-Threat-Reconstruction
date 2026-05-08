@echo off
echo =======================================================
echo   AEGIS - Restore ChromaDB Golden Baseline
echo =======================================================

if not exist "data\chromadb_baseline_archive" (
    echo [ERROR] Baseline archive not found at data\chromadb_baseline_archive
    echo Please run baseline_generator.py first and archive the chromadb directory!
    exit /b 1
)

echo [1/3] Removing current ChromaDB data...
if exist "data\chromadb" (
    rmdir /s /q "data\chromadb"
)

echo [2/3] Restoring golden baseline...
xcopy /E /I /Q "data\chromadb_baseline_archive" "data\chromadb"

echo [3/3] Done. Baseline restored successfully.
echo You can now run demo_injector.py!
