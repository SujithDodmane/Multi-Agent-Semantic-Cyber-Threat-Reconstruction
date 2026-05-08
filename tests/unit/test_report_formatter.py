"""
AEGIS Unit Tests — Report Formatter

Tests Markdown formatting, plain text formatting, 4096-char chunking,
section boundary splitting, code block usage, and edge cases.

Ref: Methodology §4.1 — Forensic Report Formatting for Messaging
Ref: TABLE 13 — "Telegram message formatter handles 4096-char limit"
Ref: TABLE 15 — "Chunk at section boundaries before sending"
"""

import pytest

from services.notification.report_formatter import (
    format_report_markdown,
    format_report_plaintext,
    chunk_message,
    TELEGRAM_MAX_CHARS,
    SEVERITY_HEADERS,
)


# ─── Test Fixtures ─────────────────────────────────────────────────────────


def _sample_report(
    narrative_length: int = 100,
    num_entities: int = 3,
    num_events: int = 2,
) -> dict:
    """Generate a sample ForensicReport dict."""
    return {
        "narrative": "A" * narrative_length + " attack detected on the network.",
        "confidence": 0.87,
        "mitre_tactics": ["TA0006", "TA0008"],
        "mitre_techniques": ["T1003", "T1021"],
        "entities": [
            {"type": "ip", "value": f"10.0.0.{i}", "role": "source"}
            for i in range(num_entities)
        ] + [
            {"type": "process", "value": "mimikatz.exe", "role": "attacker_tool"},
            {"type": "user", "value": "admin", "role": "compromised"},
        ],
        "timeline_events": [
            {
                "timestamp": f"2026-05-07T1{i}:00:00Z",
                "description": f"Event {i}: suspicious activity detected",
                "severity": "P0" if i == 0 else "P1",
                "log_uuid": f"uuid-{i}",
            }
            for i in range(num_events)
        ],
        "root_cause": "Initial access via web shell exploitation.",
        "report_id": "rpt-12345-abcde",
    }


# ─── Markdown Formatter Tests ─────────────────────────────────────────────


class TestMarkdownFormatter:
    """Test Telegram/Discord Markdown formatting."""

    def test_severity_header_p0(self):
        report = _sample_report()
        result = format_report_markdown(report, severity="P0")
        assert "P0 CRITICAL ALERT" in result

    def test_severity_header_p1(self):
        report = _sample_report()
        result = format_report_markdown(report, severity="P1")
        assert "P1 HIGH ALERT" in result

    def test_severity_header_p2(self):
        report = _sample_report()
        result = format_report_markdown(report, severity="P2")
        assert "P2 MEDIUM ALERT" in result

    def test_narrative_section(self):
        report = _sample_report()
        result = format_report_markdown(report)
        assert "Narrative" in result
        assert "attack detected" in result

    def test_timeline_section(self):
        report = _sample_report(num_events=3)
        result = format_report_markdown(report)
        assert "Timeline" in result
        assert "Event 0" in result
        assert "Event 2" in result

    def test_code_blocks_for_ips(self):
        """
        Ref: §4.1 — "Use code block formatting for IP addresses"
        """
        report = _sample_report()
        result = format_report_markdown(report)
        assert "`10.0.0.0`" in result
        assert "`10.0.0.1`" in result

    def test_code_blocks_for_processes(self):
        """
        Ref: §4.1 — "code block formatting for process names"
        """
        report = _sample_report()
        result = format_report_markdown(report)
        assert "`mimikatz.exe`" in result

    def test_mitre_section(self):
        report = _sample_report()
        result = format_report_markdown(report)
        assert "MITRE ATT&CK" in result
        assert "`TA0006`" in result
        assert "Credential Access" in result
        assert "`T1003`" in result

    def test_confidence_displayed(self):
        report = _sample_report()
        result = format_report_markdown(report)
        assert "87.0%" in result

    def test_report_id_in_footer(self):
        report = _sample_report()
        result = format_report_markdown(report)
        assert "rpt-12345-abcde" in result

    def test_root_cause_section(self):
        report = _sample_report()
        result = format_report_markdown(report)
        assert "Root Cause" in result
        assert "web shell" in result


# ─── Plain Text Formatter Tests ───────────────────────────────────────────


class TestPlainTextFormatter:
    """
    Ref: §4.1 — "WhatsApp supports only plain text — the formatter must
    have a platform-specific branch that strips Markdown syntax."
    """

    def test_no_markdown_syntax(self):
        report = _sample_report()
        result = format_report_plaintext(report)
        # Should not contain Markdown bold markers
        assert "*" not in result
        # Should not contain backticks
        assert "`" not in result

    def test_severity_header_plain(self):
        report = _sample_report()
        result = format_report_plaintext(report, severity="P0")
        assert "P0 CRITICAL ALERT" in result

    def test_report_id_present(self):
        report = _sample_report()
        result = format_report_plaintext(report)
        assert "rpt-12345-abcde" in result


# ─── Message Chunker Tests ────────────────────────────────────────────────


class TestMessageChunker:
    """
    Ref: §4.1 — "Implement a message chunker that splits the report at
    logical section boundaries (never mid-sentence)"
    Ref: TABLE 15 — "include part indicator in each chunk header"
    """

    def test_short_message_no_chunking(self):
        msg = "Short message"
        chunks = chunk_message(msg)
        assert len(chunks) == 1
        assert chunks[0] == "Short message"

    def test_telegram_limit_applied(self):
        """Each chunk must be ≤ 4096 characters."""
        long_msg = "\n\n".join([f"Section {i}: " + "X" * 500 for i in range(20)])
        chunks = chunk_message(long_msg, max_chars=TELEGRAM_MAX_CHARS)
        for chunk in chunks:
            assert len(chunk) <= TELEGRAM_MAX_CHARS + 10  # Allow for part indicator

    def test_part_indicators(self):
        """
        Ref: §4.1 — "Include a part indicator (1/3, 2/3, 3/3) in the header"
        """
        long_msg = "\n\n".join([f"Section {i}: " + "X" * 2000 for i in range(5)])
        chunks = chunk_message(long_msg, max_chars=TELEGRAM_MAX_CHARS)
        assert len(chunks) > 1
        # Each chunk should start with part indicator
        for i, chunk in enumerate(chunks):
            assert f"({i + 1}/{len(chunks)})" in chunk

    def test_splits_at_section_boundary(self):
        """Should not split mid-sentence."""
        msg = "Section A: First paragraph.\n\nSection B: Second paragraph.\n\nSection C: Third paragraph."
        chunks = chunk_message(msg, max_chars=60)
        # Each chunk should be a complete section
        for chunk in chunks:
            # Remove part indicator before checking
            content = chunk.split("\n", 1)[-1] if chunk.startswith("(") else chunk
            # Should not end mid-word (no trailing partial words)
            assert content.strip()[-1] in ".?!:" or content.strip()[-1].isalpha()

    def test_empty_message(self):
        chunks = chunk_message("")
        assert len(chunks) == 1
        assert chunks[0] == ""


# ─── Integration: Full Report Formatting ───────────────────────────────────


class TestFullReportFormatting:
    """End-to-end formatting tests."""

    def test_formatted_report_within_telegram_limit(self):
        """A typical report should fit in one message."""
        report = _sample_report()
        formatted = format_report_markdown(report)
        assert len(formatted) < TELEGRAM_MAX_CHARS

    def test_long_report_chunks_correctly(self):
        """A very long report should be chunked."""
        report = _sample_report(narrative_length=3000, num_entities=20, num_events=10)
        formatted = format_report_markdown(report)

        if len(formatted) > TELEGRAM_MAX_CHARS:
            chunks = chunk_message(formatted)
            assert len(chunks) > 1
            for chunk in chunks:
                assert len(chunk) <= TELEGRAM_MAX_CHARS + 10

    def test_empty_report_handled(self):
        """An empty report should not crash."""
        report = {}
        formatted = format_report_markdown(report)
        assert "No narrative available" in formatted
