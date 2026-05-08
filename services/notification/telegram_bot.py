"""
AEGIS — Telegram Alert Bot Service

FastAPI service that sends forensic reports and alerts to Telegram
via the Bot API. Uses direct HTTP calls (no long-polling needed —
this is a send-only bot).

Endpoints:
  POST /notify/telegram     — Send formatted ForensicReport
  POST /notify/telegram/raw — Send plain text message
  GET  /health              — Check Telegram config status

Ref: Methodology §4.1 — Forensic Report Formatting for Messaging
"""

from __future__ import annotations

import logging
import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from services.notification.report_formatter import (
    format_report_markdown,
    format_report_plaintext,
    chunk_message,
    TELEGRAM_MAX_CHARS,
)

logger = logging.getLogger("aegis.telegram")

app = FastAPI(
    title="AEGIS Notification Service",
    description="Telegram/Discord alert delivery for forensic reports",
    version="1.0.0",
)

# ─── Configuration ─────────────────────────────────────────────────────────

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
TELEGRAM_API_BASE = "https://api.telegram.org"


def _is_configured() -> bool:
    """Check if Telegram credentials are set."""
    return bool(
        TELEGRAM_BOT_TOKEN
        and TELEGRAM_CHAT_ID
        and "PASTE" not in TELEGRAM_BOT_TOKEN
        and "PASTE" not in TELEGRAM_CHAT_ID
    )


# ─── Telegram API ─────────────────────────────────────────────────────────


async def _send_telegram_message(
    text: str,
    parse_mode: str = "Markdown",
) -> dict:
    """
    Send a message via the Telegram Bot API.

    Ref: §4.1 — "Telegram supports Markdown formatting (bold, italic, code blocks)"
    """
    if not _is_configured():
        logger.warning("Telegram not configured — message not sent")
        return {"ok": False, "error": "Telegram not configured"}

    url = f"{TELEGRAM_API_BASE}/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": parse_mode,
                "disable_web_page_preview": True,
            })

            result = resp.json()

            if not result.get("ok"):
                logger.error(f"Telegram API error: {result.get('description', 'Unknown')}")
                # If Markdown parsing fails, retry with plain text
                if "can't parse" in result.get("description", "").lower():
                    logger.info("Retrying without Markdown parse mode...")
                    resp = await client.post(url, json={
                        "chat_id": TELEGRAM_CHAT_ID,
                        "text": text,
                        "disable_web_page_preview": True,
                    })
                    result = resp.json()

            return result

    except Exception as e:
        logger.error(f"Telegram send failed: {e}")
        return {"ok": False, "error": str(e)}


# ─── Request/Response Models ───────────────────────────────────────────────


class TelegramReportRequest(BaseModel):
    """Request body for POST /notify/telegram."""
    report: dict = Field(description="ForensicReport as dict")
    severity: str = Field(default="P1", description="P0/P1/P2")


class TelegramRawRequest(BaseModel):
    """Request body for POST /notify/telegram/raw."""
    message: str = Field(description="Plain text message to send")
    parse_mode: str = Field(default="Markdown")


class TelegramResponse(BaseModel):
    """Response from notification endpoints."""
    sent: bool
    chunks: int = 1
    telegram_configured: bool = True
    error: Optional[str] = None


# ─── Endpoints ─────────────────────────────────────────────────────────────


@app.post("/notify/telegram", response_model=TelegramResponse)
async def notify_telegram(request: TelegramReportRequest):
    """
    Send a formatted ForensicReport as a Telegram message.

    Handles the 4096-char limit by chunking at section boundaries.
    Ref: §4.1, TABLE 15
    """
    if not _is_configured():
        return TelegramResponse(
            sent=False,
            telegram_configured=False,
            error="Telegram not configured — set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env",
        )

    # Format the report
    formatted = format_report_markdown(request.report, severity=request.severity)

    # Chunk if needed
    chunks = chunk_message(formatted, max_chars=TELEGRAM_MAX_CHARS)

    # Send each chunk
    all_sent = True
    for chunk in chunks:
        result = await _send_telegram_message(chunk)
        if not result.get("ok"):
            all_sent = False
            logger.error(f"Chunk send failed: {result}")

    return TelegramResponse(
        sent=all_sent,
        chunks=len(chunks),
    )


@app.post("/notify/telegram/raw", response_model=TelegramResponse)
async def notify_telegram_raw(request: TelegramRawRequest):
    """Send a raw text message to Telegram."""
    if not _is_configured():
        return TelegramResponse(
            sent=False,
            telegram_configured=False,
            error="Telegram not configured",
        )

    chunks = chunk_message(request.message, max_chars=TELEGRAM_MAX_CHARS)

    all_sent = True
    for chunk in chunks:
        result = await _send_telegram_message(chunk, parse_mode=request.parse_mode)
        if not result.get("ok"):
            all_sent = False

    return TelegramResponse(sent=all_sent, chunks=len(chunks))


@app.get("/health")
async def health():
    """Check notification service health and Telegram configuration."""
    configured = _is_configured()

    # Test connection if configured
    telegram_reachable = False
    if configured:
        try:
            url = f"{TELEGRAM_API_BASE}/bot{TELEGRAM_BOT_TOKEN}/getMe"
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url)
                result = resp.json()
                telegram_reachable = result.get("ok", False)
        except Exception:
            pass

    return {
        "status": "healthy" if configured else "unconfigured",
        "telegram_configured": configured,
        "telegram_reachable": telegram_reachable,
        "telegram_chat_id": TELEGRAM_CHAT_ID[:6] + "***" if configured else "not set",
    }
