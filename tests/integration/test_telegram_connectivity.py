"""
AEGIS Integration Test — Telegram Bot Connectivity

Verifies the Telegram bot is correctly configured and can send messages.
Uses the credentials from .env.

Run with: pytest -m telegram tests/integration/test_telegram_connectivity.py -v

Ref: Methodology §4.1 — Protocol Adapters
"""

import os
import sys
from pathlib import Path

import pytest
import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Load .env manually
env_path = Path(__file__).resolve().parents[2] / ".env"
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
TELEGRAM_API = "https://api.telegram.org"


def _is_configured() -> bool:
    return bool(
        TELEGRAM_BOT_TOKEN
        and TELEGRAM_CHAT_ID
        and "PASTE" not in TELEGRAM_BOT_TOKEN
        and "PASTE" not in TELEGRAM_CHAT_ID
    )


pytestmark = pytest.mark.telegram


@pytest.mark.skipif(not _is_configured(), reason="Telegram not configured in .env")
class TestTelegramConnectivity:
    """Live Telegram bot connectivity tests."""

    def test_bot_token_valid(self):
        """
        Verify the bot token is valid by calling getMe.
        """
        url = f"{TELEGRAM_API}/bot{TELEGRAM_BOT_TOKEN}/getMe"
        resp = httpx.get(url, timeout=10.0)
        data = resp.json()

        assert data.get("ok") is True, f"Bot token invalid: {data}"
        bot_info = data.get("result", {})
        assert "username" in bot_info
        print(f"\n  [OK] Bot: @{bot_info['username']} (ID: {bot_info['id']})")

    def test_send_test_message(self):
        """
        Send a test message to the configured chat.
        """
        url = f"{TELEGRAM_API}/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        message = (
            "🛡 *AEGIS Test Alert*\n\n"
            "This is a connectivity test from the AEGIS testing suite.\n"
            "If you see this message, Telegram integration is working correctly.\n\n"
            "`Status: PASS ✅`"
        )

        resp = httpx.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }, timeout=10.0)

        data = resp.json()
        assert data.get("ok") is True, f"Send failed: {data}"
        print(f"\n  [OK] Message sent to chat {TELEGRAM_CHAT_ID}")

    def test_chat_id_reachable(self):
        """Verify the chat ID is valid and bot has access."""
        url = f"{TELEGRAM_API}/bot{TELEGRAM_BOT_TOKEN}/getChat"
        resp = httpx.post(url, json={"chat_id": TELEGRAM_CHAT_ID}, timeout=10.0)
        data = resp.json()

        assert data.get("ok") is True, f"Chat not reachable: {data}"
        chat = data.get("result", {})
        print(f"\n  [OK] Chat type: {chat.get('type')}, title/name: {chat.get('title', chat.get('first_name', 'N/A'))}")
