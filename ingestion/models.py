"""
AEGIS Ingestion — Pydantic Models (Canonical Schema)

These models are the Python representation of the JSON schemas defined in schemas/.
They serve as the single source of truth for data structures within the Python codebase.
All downstream components (embedding, correlation, timeline) consume these models.

Ref: Methodology §1.3 — Normalization to Canonical JSON Schema
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class EventType(str, enum.Enum):
    """
    Flat taxonomy of security event types.
    Ref: Methodology §1.3 — "Event type taxonomy is a flat string enum, not free text"
    """

    PROCESS_CREATION = "PROCESS_CREATION"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    FILE_WRITE = "FILE_WRITE"
    FILE_DELETE = "FILE_DELETE"
    REGISTRY_WRITE = "REGISTRY_WRITE"
    DNS_QUERY = "DNS_QUERY"
    HTTP_REQUEST = "HTTP_REQUEST"
    AUTHENTICATION_SUCCESS = "AUTHENTICATION_SUCCESS"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    AUTHENTICATION_FAILURE_BURST = "AUTHENTICATION_FAILURE_BURST"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    SERVICE_INSTALL = "SERVICE_INSTALL"
    SCHEDULED_TASK = "SCHEDULED_TASK"
    LATERAL_MOVEMENT_HINT = "LATERAL_MOVEMENT_HINT"
    EXFILTRATION_HINT = "EXFILTRATION_HINT"
    UNKNOWN = "UNKNOWN"


class Severity(str, enum.Enum):
    """Priority levels for the asyncio.PriorityQueue (lower int = higher priority)."""

    P0 = "P0"  # Critical — priority 0
    P1 = "P1"  # High — priority 1
    P2 = "P2"  # Medium — priority 2
    BENIGN = "BENIGN"  # Not queued


class NormalizedLogEntry(BaseModel):
    """
    Canonical log entry schema — immutable contract between Plane 1 and all downstream planes.

    Ref: Methodology §1.3
    Ref: schemas/normalized_log.json

    Mandatory fields are non-Optional. Optional fields populated when available.
    """

    # --- Mandatory fields ---
    log_uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), description="UUID4 generated at ingestion time")
    ingestion_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO8601 UTC timestamp of ingestion",
    )
    event_timestamp: str = Field(description="Parsed from log source, or ingestion_timestamp if absent")
    event_type: EventType = Field(description="Taxonomy classification of the event")
    hostname: str = Field(default="unknown", description="Hostname where the event occurred")
    sha256_hash: str = Field(description="SHA-256 hash of raw_payload for chain-of-custody")
    raw_payload: str = Field(description="Original log line stored verbatim")
    synthetic_intent: str = Field(default="", description="Human-readable sentence for BGE-m3 embedding")

    # --- Optional fields (populated when available) ---
    source_ip: Optional[str] = Field(default=None)
    dest_ip: Optional[str] = Field(default=None)
    source_port: Optional[int] = Field(default=None)
    dest_port: Optional[int] = Field(default=None)
    process_name: Optional[str] = Field(default=None)
    parent_process_name: Optional[str] = Field(default=None)
    user_account: Optional[str] = Field(default=None)
    event_code: Optional[str] = Field(default=None, description="Original numeric code from source system")
    file_path: Optional[str] = Field(default=None)
    registry_key: Optional[str] = Field(default=None)
    command_line_args: Optional[str] = Field(default=None)
    dns_query: Optional[str] = Field(default=None)
    http_url: Optional[str] = Field(default=None)
    http_method: Optional[str] = Field(default=None)
    bytes_sent: Optional[int] = Field(default=None)
    bytes_received: Optional[int] = Field(default=None)
    mitre_technique_hint: Optional[str] = Field(
        default=None,
        description="MITRE ATT&CK technique ID hint from intent translation",
    )
    severity_hint: Optional[Severity] = Field(
        default=None,
        description="Optional manual severity override (P0, P1, P2)",
    )

    def get_field_safe(self, field_name: str, default: str = "unknown") -> str:
        """
        Get a field value with null-safe substitution.
        Ref: Methodology §1.4 — "template renderer must substitute null fields
        with the string 'unknown' rather than leaving Python f-string formatting
        to raise a KeyError"
        """
        value = getattr(self, field_name, None)
        return str(value) if value is not None else default


class TriageOutput(BaseModel):
    """
    Output from the Triage SKILL.md.
    Ref: Abstract Report Appendix A.1
    """

    anomaly_detected: bool
    severity: Severity
    heuristic_flags: list[str] = Field(default_factory=list)
    correlation_required: bool
    confidence: float = Field(ge=0.0, le=1.0)


class CorrelationOutput(BaseModel):
    """
    Output from the Correlation SKILL.md.
    Ref: Abstract Report Appendix A.2
    """

    correlated_uuids: list[str] = Field(default_factory=list)
    cosine_scores: list[float] = Field(default_factory=list)
    cluster_size: int = 0
    temporal_span_minutes: float = 0.0
    cold_start: bool = False


class EntityNode(BaseModel):
    """Entity extracted for the knowledge graph."""

    type: str  # ip, hostname, process, user, file
    value: str
    role: str = ""


class TimelineEvent(BaseModel):
    """Individual event in the forensic timeline."""

    timestamp: str
    description: str
    severity: str = ""
    log_uuid: str = ""


class ForensicReport(BaseModel):
    """
    Final output from the Timeline SKILL.md — the forensic report.
    Ref: Abstract Report Appendix A.3
    Ref: schemas/timeline_output.json

    IMPORTANT: This schema MUST stay in sync with the Qwen 2.5 prompt schema.
    Ref: Methodology §3.4 — "The JSON output schema passed to Qwen 2.5 must
    exactly match the Pydantic model used for validation."
    """

    narrative: str
    confidence: float = Field(ge=0.0, le=1.0)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    entities: list[EntityNode] = Field(default_factory=list)
    timeline_events: list[TimelineEvent] = Field(default_factory=list)
    root_cause: Optional[str] = ""
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
