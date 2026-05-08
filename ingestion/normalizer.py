"""
AEGIS Ingestion — Log Normalizer

Transforms identified log entries into the canonical NormalizedLogEntry schema.
Each log type has a dedicated normalization function.

Ref: Methodology §1.3 — "Every log type, regardless of origin, must be transformed
into the canonical NormalizedLogEntry schema before leaving Plane 1."
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from ingestion.log_identifier import LogSource
from ingestion.models import EventType, NormalizedLogEntry

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    """Current UTC timestamp in ISO8601."""
    return datetime.now(timezone.utc).isoformat()


def _sha256(raw: str) -> str:
    """
    Compute SHA-256 hash of raw payload for chain-of-custody.
    Ref: Methodology §1.5 — "every log entry receives a SHA-256 hash of its raw_payload field"
    """
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _safe_str(value: Any) -> Optional[str]:
    """Convert value to string if not None/empty."""
    if value is None or value == "":
        return None
    return str(value)


def _safe_int(value: Any) -> Optional[int]:
    """Convert value to int if possible."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _parse_timestamp(parsed: dict[str, Any], keys: list[str]) -> str:
    """
    Try to parse a timestamp from parsed data using given key candidates.
    Falls back to current UTC time if no valid timestamp found.

    Ref: Methodology §1.3 — "event_timestamp (parsed from the log source,
    or set to ingestion_timestamp if absent)"
    """
    for key in keys:
        val = parsed.get(key)
        if val is not None:
            try:
                if isinstance(val, (int, float)):
                    # Unix timestamp (Zeek uses epoch floats)
                    return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
                return str(val)
            except (OSError, ValueError):
                continue
    return _now_iso()


# ─── Sysmon / Windows Event Log Normalization ─────────────────────────────────

# Sysmon EventID → EventType mapping
SYSMON_EVENT_MAP: dict[str, EventType] = {
    "1": EventType.PROCESS_CREATION,
    "3": EventType.NETWORK_CONNECTION,
    "5": EventType.PROCESS_CREATION,  # Process terminated (track as creation lifecycle)
    "7": EventType.PROCESS_CREATION,  # Image loaded
    "8": EventType.PROCESS_CREATION,  # CreateRemoteThread
    "10": EventType.PRIVILEGE_ESCALATION,  # Process accessed (e.g. lsass dump)
    "11": EventType.FILE_WRITE,
    "12": EventType.REGISTRY_WRITE,
    "13": EventType.REGISTRY_WRITE,
    "14": EventType.REGISTRY_WRITE,
    "15": EventType.FILE_WRITE,  # FileCreateStreamHash
    "22": EventType.DNS_QUERY,
    "23": EventType.FILE_DELETE,
}

# Windows Security EventID → EventType mapping
WINDOWS_EVENT_MAP: dict[str, EventType] = {
    "4624": EventType.AUTHENTICATION_SUCCESS,
    "4625": EventType.AUTHENTICATION_FAILURE,
    "4648": EventType.AUTHENTICATION_SUCCESS,  # Explicit credentials
    "4672": EventType.PRIVILEGE_ESCALATION,  # Special privileges assigned
    "4688": EventType.PROCESS_CREATION,
    "4689": EventType.PROCESS_CREATION,  # Process exit
    "4697": EventType.SERVICE_INSTALL,
    "4698": EventType.SCHEDULED_TASK,
    "4720": EventType.AUTHENTICATION_SUCCESS,  # Account created
    "4732": EventType.PRIVILEGE_ESCALATION,  # Member added to security group
    "4768": EventType.AUTHENTICATION_SUCCESS,  # Kerberos TGT
    "4769": EventType.AUTHENTICATION_SUCCESS,  # Kerberos service ticket
    "5140": EventType.LATERAL_MOVEMENT_HINT,  # Network share accessed
    "5145": EventType.LATERAL_MOVEMENT_HINT,  # Network share object accessed
    "1102": EventType.EXFILTRATION_HINT,  # Security log cleared
    "104": EventType.EXFILTRATION_HINT,   # System log cleared
}


def normalize_sysmon(parsed: dict[str, Any], raw_line: str) -> NormalizedLogEntry:
    """Normalize Sysmon event log entry."""
    event_id = str(parsed.get("EventID", parsed.get("event.code", "")))
    event_type = SYSMON_EVENT_MAP.get(event_id, EventType.UNKNOWN)


    process_name = _safe_str(parsed.get("Image", parsed.get("process.name", parsed.get("NewProcessName"))))
    dest_ip = _safe_str(parsed.get("DestinationIp", parsed.get("dst_ip", parsed.get("DestinationAddress"))))
    command_line_args = _safe_str(parsed.get("CommandLine", parsed.get("process.command_line")))
    
    if event_id == "10":
        event_type = EventType.PRIVILEGE_ESCALATION
        source_image = _safe_str(parsed.get("SourceImage"))
        process_name = source_image.split("\\")[-1] if source_image else "unknown"
        dest_ip = _safe_str(parsed.get("TargetImage", "unknown"))  # target process
        granted_access = _safe_str(parsed.get("GrantedAccess", "?"))
        target_image = _safe_str(parsed.get("TargetImage", "?"))
        command_line_args = f"GrantedAccess:{granted_access} Target:{target_image}"
    elif event_id == "13":
        event_type = EventType.REGISTRY_WRITE
        details = _safe_str(parsed.get("Details", "?"))
        command_line_args = details

    return NormalizedLogEntry(
        log_uuid=str(uuid.uuid4()),
        ingestion_timestamp=_now_iso(),
        event_timestamp=_parse_timestamp(parsed, ["UtcTime", "TimeCreated", "ts", "timestamp"]),
        source_ip=_safe_str(parsed.get("SourceIp", parsed.get("src_ip", parsed.get("SourceAddress")))),
        dest_ip=dest_ip,
        dest_port=_safe_int(parsed.get("DestinationPort", parsed.get("dst_port"))),
        process_name=_safe_str(parsed.get("Image", parsed.get("process.name", parsed.get("process_name", parsed.get("source", "sysmon"))))),
        parent_process_name=_safe_str(parsed.get("ParentImage", parsed.get("process.parent.name", parsed.get("ParentProcessName")))),
        user_account=_safe_str(parsed.get("User", parsed.get("user.name", parsed.get("SubjectUserName")))),
        event_type=event_type,
        event_code=event_id,
        hostname=str(parsed.get("hostname", parsed.get("Computer", parsed.get("host.name", parsed.get("ComputerName", "unknown_host"))))),
        sha256_hash=_sha256(raw_line),
        raw_payload=raw_line,
        file_path=_safe_str(parsed.get("TargetFilename", parsed.get("file.path"))),
        registry_key=_safe_str(parsed.get("TargetObject")),
        command_line_args=command_line_args,
        dns_query=_safe_str(parsed.get("QueryName")),
    )


def normalize_windows_event(parsed: dict[str, Any], raw_line: str) -> NormalizedLogEntry:
    """Normalize Windows Security Event log entry."""
    event_id = str(parsed.get("EventID", ""))
    event_type = WINDOWS_EVENT_MAP.get(event_id, EventType.UNKNOWN)

    process_name = _safe_str(parsed.get("NewProcessName", parsed.get("ProcessName")))
    user_account = _safe_str(parsed.get("TargetUserName", parsed.get("SubjectUserName")))
    command_line_args = _safe_str(parsed.get("CommandLine"))

    if event_id in ["1102", "104"]:
        event_type = EventType.EXFILTRATION_HINT
        process_name = "wevtutil.exe"
        command_line_args = f"EventLogCleared:Channel={parsed.get('Channel', 'Security')}"

    return NormalizedLogEntry(
        log_uuid=str(uuid.uuid4()),
        ingestion_timestamp=_now_iso(),
        event_timestamp=_parse_timestamp(parsed, ["TimeCreated", "timestamp", "@timestamp"]),
        source_ip=_safe_str(parsed.get("IpAddress", parsed.get("SourceNetworkAddress"))),
        dest_ip=_safe_str(parsed.get("DestAddress", parsed.get("TargetServerName"))),
        source_port=_safe_int(parsed.get("IpPort", parsed.get("SourcePort"))),
        dest_port=_safe_int(parsed.get("DestPort")),
        process_name=_safe_str(process_name) or _safe_str(parsed.get("source", "windows_event")),
        parent_process_name=_safe_str(parsed.get("ParentProcessName")),
        user_account=user_account,
        event_type=event_type,
        event_code=event_id,
        hostname=str(parsed.get("hostname", parsed.get("Computer", parsed.get("Workstation", "unknown_host")))),
        sha256_hash=_sha256(raw_line),
        raw_payload=raw_line,
        command_line_args=command_line_args,
    )


# ─── Zeek Log Normalization ──────────────────────────────────────────────────

def normalize_zeek_conn(parsed: dict[str, Any], raw_line: str) -> NormalizedLogEntry:
    """Normalize Zeek conn.log entry."""
    return NormalizedLogEntry(
        log_uuid=str(uuid.uuid4()),
        ingestion_timestamp=_now_iso(),
        event_timestamp=_parse_timestamp(parsed, ["ts"]),
        source_ip=_safe_str(parsed.get("id.orig_h")),
        dest_ip=_safe_str(parsed.get("id.resp_h")),
        source_port=_safe_int(parsed.get("id.orig_p")),
        dest_port=_safe_int(parsed.get("id.resp_p")),
        event_type=EventType.NETWORK_CONNECTION,
        process_name=_safe_str(parsed.get("source", "zeek_conn")),
        hostname=str(parsed.get("hostname", parsed.get("host", "unknown_host"))),
        sha256_hash=_sha256(raw_line),
        raw_payload=raw_line,
        bytes_sent=_safe_int(parsed.get("orig_bytes")),
        bytes_received=_safe_int(parsed.get("resp_bytes")),
    )


def normalize_zeek_dns(parsed: dict[str, Any], raw_line: str) -> NormalizedLogEntry:
    """Normalize Zeek dns.log entry."""
    return NormalizedLogEntry(
        log_uuid=str(uuid.uuid4()),
        ingestion_timestamp=_now_iso(),
        event_timestamp=_parse_timestamp(parsed, ["ts"]),
        source_ip=_safe_str(parsed.get("id.orig_h")),
        dest_ip=_safe_str(parsed.get("id.resp_h")),
        source_port=_safe_int(parsed.get("id.orig_p")),
        dest_port=_safe_int(parsed.get("id.resp_p")),
        event_type=EventType.DNS_QUERY,
        process_name=_safe_str(parsed.get("source", "zeek_dns")),
        hostname=str(parsed.get("hostname", parsed.get("host", "unknown_host"))),
        sha256_hash=_sha256(raw_line),
        raw_payload=raw_line,
        dns_query=_safe_str(parsed.get("query")),
    )


def normalize_zeek_http(parsed: dict[str, Any], raw_line: str) -> NormalizedLogEntry:
    """Normalize Zeek http.log entry."""
    host_header = _safe_str(parsed.get("host"))
    uri = _safe_str(parsed.get("uri", ""))
    full_url = f"http://{host_header}{uri}" if host_header and uri else uri

    return NormalizedLogEntry(
        log_uuid=str(uuid.uuid4()),
        ingestion_timestamp=_now_iso(),
        event_timestamp=_parse_timestamp(parsed, ["ts"]),
        source_ip=_safe_str(parsed.get("id.orig_h")),
        dest_ip=_safe_str(parsed.get("id.resp_h")),
        source_port=_safe_int(parsed.get("id.orig_p")),
        dest_port=_safe_int(parsed.get("id.resp_p")),
        event_type=EventType.HTTP_REQUEST,
        process_name=_safe_str(parsed.get("source", "zeek_http")),
        hostname=str(parsed.get("hostname", parsed.get("host", "unknown_host"))),
        sha256_hash=_sha256(raw_line),
        raw_payload=raw_line,
        http_url=full_url,
        http_method=_safe_str(parsed.get("method")),
        bytes_sent=_safe_int(parsed.get("request_body_len")),
        bytes_received=_safe_int(parsed.get("response_body_len")),
    )


def normalize_zeek_ssl(parsed: dict[str, Any], raw_line: str) -> NormalizedLogEntry:
    """Normalize Zeek ssl.log entry."""
    return NormalizedLogEntry(
        log_uuid=str(uuid.uuid4()),
        ingestion_timestamp=_now_iso(),
        event_timestamp=_parse_timestamp(parsed, ["ts"]),
        source_ip=_safe_str(parsed.get("id.orig_h")),
        dest_ip=_safe_str(parsed.get("id.resp_h")),
        source_port=_safe_int(parsed.get("id.orig_p")),
        dest_port=_safe_int(parsed.get("id.resp_p")),
        event_type=EventType.DNS_QUERY,
        process_name=_safe_str(parsed.get("source", "zeek_ssl")),
        hostname=str(parsed.get("hostname", parsed.get("host", "unknown_host"))),
        sha256_hash=_sha256(raw_line),
        raw_payload=raw_line,
        dns_query=_safe_str(parsed.get("server_name")),
    )



# ─── Firewall Log Normalization ──────────────────────────────────────────────

def normalize_firewall(parsed: dict[str, Any], raw_line: str) -> NormalizedLogEntry:
    """Normalize firewall log entry (generic)."""
    action = _safe_str(parsed.get("action", parsed.get("Action", "")))
    event_type = EventType.NETWORK_CONNECTION
    if action and action.lower() in ("drop", "deny", "block", "reject"):
        event_type = EventType.NETWORK_CONNECTION  # Still a connection event, just blocked

    return NormalizedLogEntry(
        log_uuid=str(uuid.uuid4()),
        ingestion_timestamp=_now_iso(),
        event_timestamp=_parse_timestamp(parsed, ["timestamp", "ts", "date", "time"]),
        source_ip=_safe_str(parsed.get("src_ip", parsed.get("src", parsed.get("SRC", parsed.get("source_ip"))))),
        dest_ip=_safe_str(parsed.get("dst_ip", parsed.get("dst", parsed.get("DST", parsed.get("dest_ip"))))),
        source_port=_safe_int(parsed.get("src_port", parsed.get("spt", parsed.get("SPT", parsed.get("source_port"))))),
        dest_port=_safe_int(parsed.get("dst_port", parsed.get("dpt", parsed.get("DPT", parsed.get("dest_port"))))),
        event_type=event_type,
        process_name=_safe_str(parsed.get("source", "firewall")),
        hostname=str(parsed.get("hostname", parsed.get("device", "unknown_host"))),
        sha256_hash=_sha256(raw_line),
        raw_payload=raw_line,
    )


# ─── Generic / Unknown Normalization ────────────────────────────────────────

def normalize_unknown(parsed: dict[str, Any], raw_line: str) -> NormalizedLogEntry:
    """
    Fallback normalization for unidentified log types.
    Extracts what it can and marks event_type as UNKNOWN.
    Greedy extraction: if the field name matches our schema, take it.
    """
    # Try to map event_type if present in string
    event_type_str = parsed.get("event_type", "UNKNOWN").upper()
    try:
        event_type = EventType(event_type_str)
    except ValueError:
        event_type = EventType.UNKNOWN

    return NormalizedLogEntry(
        log_uuid=str(uuid.uuid4()),
        ingestion_timestamp=_now_iso(),
        event_timestamp=_parse_timestamp(parsed, ["timestamp", "ts", "@timestamp", "time", "date", "event_timestamp"]),
        event_type=event_type,
        hostname=str(parsed.get("hostname", parsed.get("host", parsed.get("Computer", "unknown")))),
        sha256_hash=_sha256(raw_line),
        raw_payload=raw_line,
        source_ip=_safe_str(parsed.get("source_ip", parsed.get("src_ip", parsed.get("src")))),
        dest_ip=_safe_str(parsed.get("dest_ip", parsed.get("dst_ip", parsed.get("dst")))),
        source_port=_safe_int(parsed.get("source_port", parsed.get("src_port"))),
        dest_port=_safe_int(parsed.get("dest_port", parsed.get("dst_port"))),
        process_name=_safe_str(parsed.get("process_name", parsed.get("process.name", parsed.get("Image")))),
        parent_process_name=_safe_str(parsed.get("parent_process_name", parsed.get("ParentImage"))),
        user_account=_safe_str(parsed.get("user_account", parsed.get("User", parsed.get("user.name")))),
        file_path=_safe_str(parsed.get("file_path", parsed.get("TargetFilename"))),
        command_line_args=_safe_str(parsed.get("command_line_args", parsed.get("CommandLine"))),
        synthetic_intent=_safe_str(parsed.get("synthetic_intent")),
        severity_hint=_safe_str(parsed.get("severity", parsed.get("priority", parsed.get("severity_hint")))),
    )


# ─── Main Normalization Router ──────────────────────────────────────────────

# Map LogSource → normalizer function
NORMALIZER_MAP = {
    LogSource.SYSMON: normalize_sysmon,
    LogSource.WINDOWS_EVENT: normalize_windows_event,
    LogSource.ZEEK_CONN: normalize_zeek_conn,
    LogSource.ZEEK_DNS: normalize_zeek_dns,
    LogSource.ZEEK_HTTP: normalize_zeek_http,
    LogSource.ZEEK_SSL: normalize_zeek_ssl,
    LogSource.FIREWALL: normalize_firewall,
    LogSource.SYSLOG: normalize_unknown,  # Syslog uses generic for now
    LogSource.UNKNOWN: normalize_unknown,
}


def normalize(
    log_source: LogSource,
    parsed: dict[str, Any],
    raw_line: str,
) -> NormalizedLogEntry:
    """
    Route to the appropriate normalizer based on identified log source.

    Ref: Methodology §1.3 — "Every log type, regardless of origin, must be
    transformed into the canonical NormalizedLogEntry schema"
    """
    normalizer = NORMALIZER_MAP.get(log_source, normalize_unknown)
    try:
        entry = normalizer(parsed, raw_line)
        return entry
    except Exception as e:
        logger.error(f"Normalization failed for {log_source}: {e}")
        # Even on failure, produce a valid entry with what we have
        return NormalizedLogEntry(
            log_uuid=str(uuid.uuid4()),
            ingestion_timestamp=_now_iso(),
            event_timestamp=_now_iso(),
            event_type=EventType.UNKNOWN,
            hostname="unknown",
            sha256_hash=_sha256(raw_line),
            raw_payload=raw_line,
        )
