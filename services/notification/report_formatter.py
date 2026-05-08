"""
AEGIS — Forensic Report Formatter

Transforms ForensicReport Pydantic objects into human-readable messages
for delivery via Telegram, Discord, or plain text fallback.

Key features:
  - Severity-colored header (P0 CRITICAL / P1 HIGH / P2 MEDIUM)
  - Code block formatting for IPs, processes, file paths (Telegram/Discord)
  - MITRE ATT&CK section with tactic/technique IDs
  - 4096-char chunker for Telegram's message limit
  - Section-boundary splitting (never mid-sentence)

Ref: Methodology §4.1 — Forensic Report Formatting for Messaging
Ref: TABLE 15 — "Telegram 4096-char message limit exceeded mid-sentence"
"""

from __future__ import annotations

import re
from typing import Optional

# ─── Constants ─────────────────────────────────────────────────────────────

TELEGRAM_MAX_CHARS = 4096

SEVERITY_HEADERS = {
    "P0": "🔴 *P0 CRITICAL ALERT*",
    "P1": "🟠 *P1 HIGH ALERT*",
    "P2": "🟡 *P2 MEDIUM ALERT*",
}

SEVERITY_HEADERS_PLAIN = {
    "P0": "⚠️ P0 CRITICAL ALERT",
    "P1": "⚠️ P1 HIGH ALERT",
    "P2": "P2 MEDIUM ALERT",
}

# MITRE tactic ID → name mapping
MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}


# ─── Markdown Formatter (Telegram / Discord) ──────────────────────────────


def format_report_markdown(
    report: dict,
    severity: str = "P1",
    include_header: bool = True,
) -> str:
    """
    Format a ForensicReport dict as Telegram-compatible Markdown.

    Ref: §4.1 — "Telegram supports Markdown formatting (bold, italic, code blocks).
    Use code block formatting for IP addresses, process names, and file paths."

    Args:
        report: ForensicReport as dict
        severity: P0/P1/P2
        include_header: Whether to include severity header

    Returns:
        Markdown-formatted string
    """
    sections = []

    # --- Severity Header ---
    if include_header:
        header = SEVERITY_HEADERS.get(severity, SEVERITY_HEADERS["P1"])
        sections.append(header)
        sections.append("")  # blank line

    # --- Narrative ---
    narrative = report.get("narrative", "No narrative available.")
    sections.append("📋 *Narrative*")
    sections.append(narrative)
    sections.append("")

    # --- Timeline Events ---
    timeline_events = report.get("timeline_events", [])
    if timeline_events:
        sections.append("⏱ *Timeline*")
        for event in timeline_events:
            ts = event.get("timestamp", "??:??")
            desc = event.get("description", "")
            sev_icon = "🔴" if event.get("severity") == "P0" else "🟡"
            sections.append(f"  {sev_icon} `{ts}` — {desc}")
        sections.append("")

    # --- Entities ---
    entities = report.get("entities", [])
    if entities:
        sections.append("🎯 *Entities*")
        for entity in entities:
            etype = entity.get("type", "unknown")
            value = entity.get("value", "")
            role = entity.get("role", "")
            # Use code blocks for IPs, processes, paths
            # Ref: §4.1 — "code block formatting for IP addresses,
            # process names, and file paths"
            if etype in ("ip", "process", "file"):
                value_fmt = f"`{value}`"
            else:
                value_fmt = value
            role_str = f" ({role})" if role else ""
            sections.append(f"  • {etype} {value_fmt}{role_str}")
        sections.append("")

    # --- MITRE ATT&CK ---
    tactics = report.get("mitre_tactics", [])
    techniques = report.get("mitre_techniques", [])
    if tactics or techniques:
        sections.append("🛡 *MITRE ATT&CK*")
        if tactics:
            for tactic_id in tactics:
                tactic_name = MITRE_TACTICS.get(tactic_id, tactic_id)
                sections.append(f"  • Tactic: `{tactic_id}` — {tactic_name}")
        if techniques:
            sections.append(f"  • Techniques: {', '.join(f'`{t}`' for t in techniques)}")
        sections.append("")

    # --- Root Cause ---
    root_cause = report.get("root_cause", "")
    if root_cause:
        sections.append("🔍 *Root Cause*")
        sections.append(root_cause)
        sections.append("")

    # --- Confidence ---
    confidence = report.get("confidence", 0.0)
    confidence_pct = round(confidence * 100, 1)
    bar_filled = int(confidence_pct / 10)
    bar = "█" * bar_filled + "░" * (10 - bar_filled)
    sections.append(f"📊 *Confidence:* {confidence_pct}% [{bar}]")
    sections.append("")

    # --- Footer ---
    report_id = report.get("report_id", "unknown")
    sections.append(f"🆔 Report: `{report_id}`")

    return "\n".join(sections)


# ─── Plain Text Formatter (WhatsApp / Fallback) ───────────────────────────


def format_report_plaintext(
    report: dict,
    severity: str = "P1",
) -> str:
    """
    Format a ForensicReport as plain text (no Markdown).

    Ref: §4.1 — "WhatsApp supports only plain text — the formatter must
    have a platform-specific branch that strips Markdown syntax."
    """
    sections = []

    # Header
    header = SEVERITY_HEADERS_PLAIN.get(severity, SEVERITY_HEADERS_PLAIN["P1"])
    sections.append(header)
    sections.append("=" * 40)
    sections.append("")

    # Narrative
    sections.append("NARRATIVE:")
    sections.append(report.get("narrative", "No narrative available."))
    sections.append("")

    # Timeline
    timeline_events = report.get("timeline_events", [])
    if timeline_events:
        sections.append("TIMELINE:")
        for event in timeline_events:
            ts = event.get("timestamp", "??:??")
            desc = event.get("description", "")
            sections.append(f"  [{ts}] {desc}")
        sections.append("")

    # Entities
    entities = report.get("entities", [])
    if entities:
        sections.append("ENTITIES:")
        for entity in entities:
            etype = entity.get("type", "unknown")
            value = entity.get("value", "")
            role = entity.get("role", "")
            role_str = f" ({role})" if role else ""
            sections.append(f"  [{etype}] {value}{role_str}")
        sections.append("")

    # MITRE
    tactics = report.get("mitre_tactics", [])
    techniques = report.get("mitre_techniques", [])
    if tactics or techniques:
        sections.append("MITRE ATT&CK:")
        for tid in tactics:
            tname = MITRE_TACTICS.get(tid, tid)
            sections.append(f"  Tactic: {tid} - {tname}")
        if techniques:
            sections.append(f"  Techniques: {', '.join(techniques)}")
        sections.append("")

    # Root Cause
    root_cause = report.get("root_cause", "")
    if root_cause:
        sections.append(f"ROOT CAUSE: {root_cause}")
        sections.append("")

    # Confidence
    confidence = report.get("confidence", 0.0)
    sections.append(f"CONFIDENCE: {round(confidence * 100, 1)}%")
    sections.append("")

    # Footer
    sections.append(f"Report ID: {report.get('report_id', 'unknown')}")

    return "\n".join(sections)


# ─── Message Chunker ──────────────────────────────────────────────────────


def chunk_message(
    message: str,
    max_chars: int = TELEGRAM_MAX_CHARS,
    header_prefix: str = "",
) -> list[str]:
    """
    Split a long message into chunks at section boundaries.

    Ref: §4.1 — "Implement a message chunker that splits the report at
    logical section boundaries (never mid-sentence) and sends each chunk
    as a sequential message in the same chat."

    Ref: TABLE 15 — "Chunk at section boundaries before sending;
    include part indicator in each chunk header"

    Args:
        message: The full formatted message
        max_chars: Maximum characters per chunk (4096 for Telegram)
        header_prefix: Optional prefix for the severity header

    Returns:
        List of message chunks, each within max_chars
    """
    if len(message) <= max_chars:
        return [message]

    # Split into sections by double newline (section boundary)
    sections = message.split("\n\n")
    chunks = []
    current_chunk = ""

    for section in sections:
        # If adding this section exceeds the limit
        candidate = (current_chunk + "\n\n" + section).strip() if current_chunk else section

        if len(candidate) <= max_chars:
            current_chunk = candidate
        else:
            # Save current chunk if it has content
            if current_chunk:
                chunks.append(current_chunk)

            # If a single section is too long, split by lines
            if len(section) > max_chars:
                lines = section.split("\n")
                current_chunk = ""
                for line in lines:
                    line_candidate = (current_chunk + "\n" + line).strip() if current_chunk else line
                    if len(line_candidate) <= max_chars:
                        current_chunk = line_candidate
                    else:
                        if current_chunk:
                            chunks.append(current_chunk)
                        # If a single line is too long, hard split
                        if len(line) > max_chars:
                            for i in range(0, len(line), max_chars):
                                chunks.append(line[i:i + max_chars])
                            current_chunk = ""
                        else:
                            current_chunk = line
            else:
                current_chunk = section

    # Don't forget the last chunk
    if current_chunk:
        chunks.append(current_chunk)

    # Add part indicators
    if len(chunks) > 1:
        total = len(chunks)
        chunks = [
            f"({i + 1}/{total})\n{chunk}"
            for i, chunk in enumerate(chunks)
        ]

    return chunks
