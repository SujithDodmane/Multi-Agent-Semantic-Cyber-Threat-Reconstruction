"""
AEGIS — Log Sanitizer

Strips dangerous patterns from log text before sending to LLM.
Prevents prompt injection attacks via crafted log entries.

Ref: TABLE 14 — "Log sanitization strips code blocks and instruction
patterns before LLM injection"
"""

from __future__ import annotations

import re
import unicodedata


# ─── Patterns to Strip ────────────────────────────────────────────────────

# Markdown code blocks (could embed instructions)
_CODE_BLOCK_RE = re.compile(r"```[\s\S]*?```", re.MULTILINE)

# LLM instruction injection patterns
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"system\s*:", re.IGNORECASE),
    re.compile(r"assistant\s*:", re.IGNORECASE),
    re.compile(r"user\s*:", re.IGNORECASE),
    re.compile(r"<\|?(system|user|assistant|im_start|im_end)\|?>", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
    re.compile(r"\[/INST\]", re.IGNORECASE),
    re.compile(r"<<SYS>>", re.IGNORECASE),
    re.compile(r"<</SYS>>", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a\s+)?", re.IGNORECASE),
    re.compile(r"forget\s+(everything|all)", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"override\s+(system|safety)", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"do\s+not\s+follow\s+(the\s+)?rules?", re.IGNORECASE),
    re.compile(r"pretend\s+(you\s+are|to\s+be)", re.IGNORECASE),
]

# Unicode control characters (except common whitespace)
_CONTROL_CHAR_KEEP = {"\n", "\r", "\t"}


def sanitize_log_text(text: str) -> str:
    """
    Sanitize log text for safe LLM consumption.

    Strips:
      - Markdown code blocks
      - LLM prompt injection patterns
      - Unicode control characters
      - Excessive whitespace

    Returns:
        Sanitized text safe for LLM input
    """
    if not text:
        return ""

    result = text

    # 1. Strip code blocks
    result = _CODE_BLOCK_RE.sub("[CODE_BLOCK_REMOVED]", result)

    # 2. Strip injection patterns
    for pattern in _INJECTION_PATTERNS:
        result = pattern.sub("[SANITIZED]", result)

    # 3. Remove unicode control characters (keep \n \r \t)
    cleaned_chars = []
    for ch in result:
        if unicodedata.category(ch).startswith("C") and ch not in _CONTROL_CHAR_KEEP:
            continue  # Skip control characters
        cleaned_chars.append(ch)
    result = "".join(cleaned_chars)

    # 4. Normalize excessive whitespace
    result = re.sub(r"\n{3,}", "\n\n", result)  # Max 2 consecutive newlines
    result = re.sub(r"[ \t]{4,}", "   ", result)  # Max 3 consecutive spaces

    return result.strip()


def is_potentially_malicious(text: str) -> bool:
    """
    Check if text contains potential injection patterns.

    Returns True if any injection pattern is detected.
    Does NOT modify the text — use sanitize_log_text for that.
    """
    if not text:
        return False

    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            return True

    if _CODE_BLOCK_RE.search(text):
        return True

    return False
