"""
AEGIS — Python-side Circuit Breaker Wrappers

Wraps downstream HTTP calls (embedding service, Ollama) with pybreaker
circuit breakers. When a service fails repeatedly, the circuit opens
and requests fail fast without waiting for timeouts.

Ref: Methodology §3.5 — Circuit Breaker Implementation
  - failure_threshold=3 (three consecutive failures open the circuit)
  - recovery_timeout=60 (60 seconds in OPEN before HALF-OPEN)
  - Expected exceptions: Timeout, ConnectionError (NOT 400 HTTPError)
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

import httpx
import pybreaker

logger = logging.getLogger("aegis.circuit_breaker")


def create_breaker(
    name: str,
    failure_threshold: int = 3,
    recovery_timeout: int = 60,
) -> pybreaker.CircuitBreaker:
    """
    Create a circuit breaker for a downstream service.

    Ref: §3.5 — "Configure one CircuitBreaker instance per downstream endpoint"
    """

    class AegisListener(pybreaker.CircuitBreakerListener):
        """Log circuit state transitions."""

        def state_change(self, cb, old_state, new_state):
            logger.warning(
                f"[CIRCUIT BREAKER] {cb.name}: {old_state.name} → {new_state.name}"
            )
            if new_state == pybreaker.STATE_OPEN:
                logger.error(
                    f"[CIRCUIT BREAKER] {cb.name} is OPEN — "
                    f"requests will fail fast for {cb._recovery_timeout}s"
                )

    return pybreaker.CircuitBreaker(
        name=name,
        fail_max=failure_threshold,
        reset_timeout=recovery_timeout,
        exclude=[
            # Ref: §3.5 — "not requests.HTTPError with status 400
            # (a 400 error means the service is up but the request was malformed)"
            lambda e: isinstance(e, httpx.HTTPStatusError) and e.response.status_code == 400,
        ],
        listeners=[AegisListener()],
    )


# ─── Pre-built Breakers ───────────────────────────────────────────────────

embedding_breaker = create_breaker("embedding-service")
ollama_breaker = create_breaker("ollama-inference")
chromadb_breaker = create_breaker("chromadb")
correlation_breaker = create_breaker("correlation-service")


# ─── Protected HTTP Calls ──────────────────────────────────────────────────


async def protected_post(
    breaker: pybreaker.CircuitBreaker,
    url: str,
    json_data: dict,
    timeout: float = 30.0,
) -> Optional[dict]:
    """
    Make an HTTP POST call protected by a circuit breaker.

    Ref: §3.5 — When circuit is OPEN:
    "write the pending work item to the dead-letter queue, emit a notification
    that the AEGIS analysis pipeline is degraded"

    Returns response JSON or None if the breaker is open/call fails.
    """
    try:
        @breaker
        async def _call():
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, json=json_data)
                resp.raise_for_status()
                return resp.json()

        return await _call()

    except pybreaker.CircuitBreakerError:
        logger.error(
            f"[CIRCUIT OPEN] {breaker.name}: request blocked — "
            f"service is down, will retry after recovery timeout"
        )
        return None

    except (httpx.ConnectError, httpx.TimeoutException) as e:
        logger.error(f"[{breaker.name}] Connection/timeout error: {e}")
        return None

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 400:
            # Client error — service is up, request is bad
            logger.warning(f"[{breaker.name}] Client error (400): {e}")
            raise  # Don't swallow client bugs
        logger.error(f"[{breaker.name}] Server error: {e}")
        return None

    except Exception as e:
        logger.error(f"[{breaker.name}] Unexpected error: {e}")
        return None


async def protected_get(
    breaker: pybreaker.CircuitBreaker,
    url: str,
    timeout: float = 5.0,
) -> Optional[dict]:
    """Make an HTTP GET call protected by a circuit breaker."""
    try:
        @breaker
        async def _call():
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                return resp.json()

        return await _call()

    except pybreaker.CircuitBreakerError:
        logger.error(f"[CIRCUIT OPEN] {breaker.name}: GET blocked")
        return None

    except Exception as e:
        logger.error(f"[{breaker.name}] GET error: {e}")
        return None
