# AEGIS HEARTBEAT — Continuous SOC Monitoring Loop

## Poll Ingestion Queue
- **Schedule:** Every 30 seconds
- **Condition:** Check Python ingestion queue for new log entries
- **Action:** Poll `GET http://localhost:8002/queue/next` with 200ms HTTP timeout
  - If entry found: write to Cognitive RAM at `context:triage:{log_uuid}` and trigger Triage skill
  - If no entry (empty queue): skip this tick, continue monitoring
  - If HTTP error: check circuit breaker state, log degradation warning
- **Timeout:** 200ms — if Python service is slow, skip tick and retry next cycle
- **Priority:** Always process P0 entries before P1, P1 before P2

## Circuit Breaker Health Check
- **Schedule:** Every 2 minutes
- **Condition:** Verify all downstream Python services are responsive
- **Action:**
  - Check embedding service: `GET http://localhost:8001/health`
  - Check correlation service: `GET http://localhost:8003/health`
  - Check synthesizer service: `GET http://localhost:8004/health`
  - If any service unhealthy: update circuit breaker state, emit degradation alert via Protocol Adapter
- **On Failure:** Log to `dead_letter_queue`, notify analyst via Telegram

## Queue Depth Monitor
- **Schedule:** Every 5 minutes
- **Condition:** Check queue backpressure metrics
- **Action:** Poll `GET http://localhost:8002/queue/stats`
  - If depth > 50: emit backpressure warning
  - Log total_enqueued, total_dropped metrics
