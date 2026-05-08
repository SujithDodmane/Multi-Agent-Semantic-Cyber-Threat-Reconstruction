"""
AEGIS Ingestion — Log Sanitization Layer

Strips potentially dangerous content from log payloads before they are
passed to the LLM context. Defends against prompt injection via crafted logs.

Ref: Methodology §3.2 (Task 3.2) — "Implement log sanitization layer
(prompt injection defense)"
Ref: Abstract Report §3.3 — "If an attacker knows the monitored log path,
a crafted log entry containing LLM-formatted instructions could attempt
prompt injection against the Timeline Agent"
Ref: Abstract Report §4.1 — "Sanitize all log payloads before LLM context
injection by stripping executable code blocks, markdown formatting, and
instruction-patterned strings."
"""

from __future__ import annotations

import re
import logging

logger = logging.getLogger(__name__)

# Patterns that could be used for prompt injection
INSTRUCTION_PATTERNS = [
    # Markdown code blocks
    re.compile(r"```[\s\S]*?```", re.MULTILINE),
    # Inline code
    re.compile(r"`[^`]+`"),
    # Common LLM instruction patterns
    re.compile(r"(?i)(ignore|forget|disregard)\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|context)", re.IGNORECASE),
    re.compile(r"(?i)you\s+are\s+now\s+a", re.IGNORECASE),
    re.compile(r"(?i)system\s*:\s*", re.IGNORECASE),
    re.compile(r"(?i)assistant\s*:\s*", re.IGNORECASE),
    re.compile(r"(?i)user\s*:\s*", re.IGNORECASE),
    re.compile(r"(?i)<\|.*?\|>"),  # Chat template markers
    re.compile(r"(?i)\[INST\].*?\[/INST\]", re.DOTALL),  # Llama-style
    re.compile(r"(?i)<<SYS>>.*?<</SYS>>", re.DOTALL),  # Llama-style system
    # HTML/XML script injection
    re.compile(r"<script[\s>][\s\S]*?</script>", re.IGNORECASE),
    re.compile(r"<iframe[\s>][\s\S]*?</iframe>", re.IGNORECASE),
]

# Characters to strip (control characters except common whitespace)
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_for_llm(text: str) -> str:
    """
    Sanitize a text string before including it in LLM context.

    Strips:
    - Markdown code blocks and inline code
    - LLM instruction patterns (prompt injection attempts)
    - HTML/XML script tags
    - Control characters

    Returns the sanitized string.
    """
    if not text:
        return text

    sanitized = text

    # Strip instruction patterns
    for pattern in INSTRUCTION_PATTERNS:
        sanitized = pattern.sub("[SANITIZED]", sanitized)

    # Strip control characters
    sanitized = CONTROL_CHARS.sub("", sanitized)

    # Limit length to prevent context window overflow
    max_len = 2000  # Reasonable limit for a single log entry
    if len(sanitized) > max_len:
        sanitized = sanitized[:max_len] + "...[TRUNCATED]"

    if sanitized != text:
        logger.debug("Log payload sanitized — potential injection content removed")

    return sanitized


def sanitize_log_entry_fields(entry_dict: dict) -> dict:
    """
    Sanitize all string fields in a log entry dictionary.
    Applied before passing log data to LLM prompts.
    """
    sanitized = {}
    for key, value in entry_dict.items():
        if isinstance(value, str) and key not in ("sha256_hash", "log_uuid"):
            sanitized[key] = sanitize_for_llm(value)
        else:
            sanitized[key] = value
    return sanitized
