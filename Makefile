# ==============================================================================
# AEGIS Makefile — Common development commands
# Usage: make <target>
# ==============================================================================

.PHONY: setup run-ingestion run-embedding run-graph test docker-up docker-down inject-attack lint clean

# --- Setup ---
setup:
	py -3.10 -m venv claw
	claw\Scripts\python -m pip install --upgrade pip
	claw\Scripts\pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124
	claw\Scripts\pip install -e ".[dev]"
	copy .env.example .env

# --- Run Services ---
run-ingestion:
	claw\Scripts\python -m ingestion.daemon

run-embedding:
	claw\Scripts\uvicorn services.embedding.app:app --host 0.0.0.0 --port 8001

run-graph:
	claw\Scripts\python -m services.graph.server

# --- Testing ---
test:
	claw\Scripts\pytest tests/ -v

test-unit:
	claw\Scripts\pytest tests/unit/ -v

test-integration:
	claw\Scripts\pytest tests/integration/ -v

test-stress:
	claw\Scripts\pytest tests/stress/ -v --timeout=120

# --- Docker ---
docker-up:
	docker compose -f infra/docker-compose.yml up -d

docker-down:
	docker compose -f infra/docker-compose.yml down

docker-build:
	docker compose -f infra/docker-compose.yml build

# --- Demo ---
inject-attack:
	claw\Scripts\python scripts/inject_attack.py

generate-baseline:
	claw\Scripts\python scripts/generate_baseline.py

# --- Linting ---
lint:
	claw\Scripts\ruff check .
	claw\Scripts\black --check .

format:
	claw\Scripts\ruff check --fix .
	claw\Scripts\black .

# --- Cleanup ---
clean:
	del /S /Q __pycache__ 2>nul
	del /S /Q *.pyc 2>nul
	del /Q data\aegis.db 2>nul
