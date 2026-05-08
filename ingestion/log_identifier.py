"""
AEGIS Ingestion — Log Type Identification

Deterministic, fast log type identification using file path patterns and field
signature matching. Zero ML, zero heuristics.

Ref: Methodology §1.2 — "This identification must be deterministic and fast"

The identification registry is a priority-ordered list of checks that
short-circuits on the first match. Malformed entries are routed to a dedicated
'malformed' queue rather than crashing the daemon.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class LogSource(str, Enum):
    """Supported log source types."""

    SYSMON = "sysmon"
    WINDOWS_EVENT = "windows_event"
    ZEEK_CONN = "zeek_conn"
    ZEEK_DNS = "zeek_dns"
    ZEEK_HTTP = "zeek_http"
    ZEEK_SSL = "zeek_ssl"
    FIREWALL = "firewall"
    SYSLOG = "syslog"
    UNKNOWN = "unknown"


# --- Path pattern registry ---
# Ref: Methodology §1.2 — "File path patterns"
PATH_PATTERNS: list[tuple[re.Pattern, LogSource]] = [
    (re.compile(r"sysmon|Microsoft-Windows-Sysmon", re.IGNORECASE), LogSource.SYSMON),
    (re.compile(r"zeek.*dns|bro.*dns", re.IGNORECASE), LogSource.ZEEK_DNS),
    (re.compile(r"zeek.*http|bro.*http", re.IGNORECASE), LogSource.ZEEK_HTTP),
    (re.compile(r"zeek.*ssl|bro.*ssl", re.IGNORECASE), LogSource.ZEEK_SSL),
    (re.compile(r"zeek|bro", re.IGNORECASE), LogSource.ZEEK_CONN),
    (re.compile(r"firewall|pf\.log|iptables|ufw", re.IGNORECASE), LogSource.FIREWALL),
]


@dataclass
class FieldSignature:
    """A single field-based identification rule."""

    field_name: str
    expected_values: Optional[list[str]] = None  # None means "field exists"
    source: LogSource = LogSource.UNKNOWN
    priority: int = 0


# --- Field signature registry ---
# Ref: Methodology §1.2 — "Field signature matching"
FIELD_SIGNATURES: list[FieldSignature] = [
    # Identification by source field (common in scenario logs)
    FieldSignature(field_name="source", expected_values=["sysmon"], source=LogSource.SYSMON, priority=1),
    FieldSignature(field_name="source", expected_values=["windows_event"], source=LogSource.WINDOWS_EVENT, priority=2),
    FieldSignature(field_name="source", expected_values=["zeek_conn"], source=LogSource.ZEEK_CONN, priority=3),
    FieldSignature(field_name="source", expected_values=["zeek_dns"], source=LogSource.ZEEK_DNS, priority=4),
    FieldSignature(field_name="source", expected_values=["zeek_http"], source=LogSource.ZEEK_HTTP, priority=5),
    FieldSignature(field_name="source", expected_values=["zeek_ssl"], source=LogSource.ZEEK_SSL, priority=6),
    FieldSignature(field_name="source", expected_values=["firewall"], source=LogSource.FIREWALL, priority=7),
    
    # Windows Event Log — contains EventID
    FieldSignature(field_name="EventID", source=LogSource.WINDOWS_EVENT, priority=10),
    FieldSignature(field_name="event.code", source=LogSource.SYSMON, priority=11),
    # Zeek logs — _path field identifies the stream
    FieldSignature(field_name="_path", expected_values=["dns"], source=LogSource.ZEEK_DNS, priority=3),
    FieldSignature(field_name="_path", expected_values=["http"], source=LogSource.ZEEK_HTTP, priority=4),
    FieldSignature(field_name="_path", expected_values=["ssl", "x509"], source=LogSource.ZEEK_SSL, priority=5),
    FieldSignature(field_name="_path", expected_values=["conn"], source=LogSource.ZEEK_CONN, priority=6),
    FieldSignature(field_name="_path", source=LogSource.ZEEK_CONN, priority=7),  # Any Zeek
]

# RFC 5424 syslog header pattern
SYSLOG_PATTERN = re.compile(
    r"^<\d+>\d?\s*\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}"  # <PRI>timestamp
    r"|^<\d+>1\s+"  # RFC 5424 structured
)


def parse_log_line(line: str) -> tuple[Optional[dict[str, Any]], str]:
    """
    Attempt to parse a raw log line into a structured dict.

    Returns (parsed_dict, format_type) where format_type is 'json', 'kv', 'syslog', or 'raw'.

    Ref: Methodology §1.2 — "once a line is parsed as JSON (or key=value pairs)"
    """
    line = line.strip()
    if not line:
        return None, "empty"

    # Try JSON first
    try:
        parsed = json.loads(line)
        if isinstance(parsed, dict):
            return parsed, "json"
    except (json.JSONDecodeError, ValueError):
        pass

    # Try key=value (CEF-like) format
    kv_pairs = {}
    kv_pattern = re.compile(r'(\w+)=(?:"([^"]*?)"|(\S+))')
    matches = kv_pattern.findall(line)
    if len(matches) >= 3:  # At least 3 KV pairs to be considered KV format
        for key, quoted_val, unquoted_val in matches:
            kv_pairs[key] = quoted_val if quoted_val else unquoted_val
        return kv_pairs, "kv"

    # Check for syslog format
    if SYSLOG_PATTERN.match(line):
        return {"raw_syslog": line}, "syslog"

    # Raw — unparseable but not malformed (could be a valid but unknown format)
    return {"raw_line": line}, "raw"


def identify_from_path(file_path: str) -> Optional[LogSource]:
    """
    Identify log type from file path patterns.

    Ref: Methodology §1.2 — "if the monitored path contains 'sysmon'..."
    """
    for pattern, source in PATH_PATTERNS:
        if pattern.search(file_path):
            return source
    return None


def identify_from_fields(parsed: dict[str, Any]) -> Optional[LogSource]:
    """
    Identify log type from field signatures.

    Short-circuits on first match (ordered by priority).
    Ref: Methodology §1.2 — "priority-ordered list of (field_name, expected_values) tuples"
    """
    sorted_sigs = sorted(FIELD_SIGNATURES, key=lambda s: s.priority)

    for sig in sorted_sigs:
        if sig.field_name in parsed:
            if sig.expected_values is None:
                return sig.source
            field_val = str(parsed[sig.field_name])
            if field_val in sig.expected_values:
                return sig.source
    return None


def identify_log_type(file_path: str, raw_line: str) -> tuple[LogSource, Optional[dict[str, Any]], str]:
    """
    Main identification function. Combines path + field identification.

    Returns (log_source, parsed_dict, format_type).

    Ref: Methodology §1.2 — "The identification layer must be wrapped in exception
    handling that routes unparseable entries to a dedicated 'malformed' queue"
    """
    try:
        # 1. Try path-based identification first
        path_source = identify_from_path(file_path)

        # 2. Parse the line
        parsed, format_type = parse_log_line(raw_line)
        if parsed is None:
            return LogSource.UNKNOWN, None, "empty"

        # 3. Try field-based identification
        field_source = identify_from_fields(parsed) if parsed else None

        # 4. Combine: field-based overrides path-based (more specific)
        final_source = field_source or path_source or LogSource.UNKNOWN

        return final_source, parsed, format_type

    except Exception as e:
        # Methodology §1.2: Route malformed entries to error queue, don't crash
        logger.warning(f"Failed to identify log line: {e}")
        return LogSource.UNKNOWN, None, "malformed"
