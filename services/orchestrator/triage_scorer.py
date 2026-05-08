"""
AEGIS — Triage Scoring Engine (Python Implementation)

Mirror of the Node.js triage scoring in openclaw/index.js.
Used for:
1. Unit testing the scoring logic without Node.js dependency
2. Fallback if Node.js orchestrator is unavailable
3. CI validation of scoring correctness

The canonical implementation is in OpenClaw (Node.js). This Python
version must stay in sync.

Ref: Methodology §2.2 — Triage SKILL.md Implementation Logic
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

import yaml

from ingestion.models import EventType, NormalizedLogEntry

logger = logging.getLogger("aegis.triage")

# ─── Defaults (overridden by threat_lists.yaml) ────────────────────────────

DEFAULT_DANGEROUS_PROCESSES = [
    "mimikatz", "mimikatz.exe", "procdump", "procdump.exe",
    "psexec", "psexec.exe", "wce", "wce.exe",
    "fgdump", "fgdump.exe", "gsecdump", "gsecdump.exe",
    "lsass", "ntdsutil", "ntdsutil.exe",
    "lazagne", "lazagne.exe", "rubeus", "rubeus.exe",
    "sharphound", "sharphound.exe",
]

DEFAULT_C2_PORTS = [4444, 5555, 1337, 8888, 9001, 6666, 6667, 31337, 12345]

DEFAULT_THRESHOLDS = {"P0": 61, "P1": 41, "P2": 21, "BENIGN": 0}

DEFAULT_WEIGHTS = {
    "dangerous_process": 40,
    "webserver_parent_cmd_child": 35,
    "c2_port": 30,
    "privilege_escalation_event": 50,
    "exfiltration_hint_event": 50,
    "ip_historical_correlation": 20,
}

WEB_SERVERS = {"apache2", "apache2.exe", "nginx", "nginx.exe", "w3wp.exe", "tomcat", "httpd", "httpd.exe"}
CMD_SHELLS = {"cmd.exe", "powershell.exe", "bash", "sh"}


class TriageScorer:
    """
    Heuristic scoring engine matching the methodology decision tree.

    Ref: Methodology §2.2 — Triage SKILL.md Implementation Logic
    """

    def __init__(self, config_path: Optional[Path] = None):
        self.dangerous_processes = list(DEFAULT_DANGEROUS_PROCESSES)
        self.c2_ports = list(DEFAULT_C2_PORTS)
        self.thresholds = dict(DEFAULT_THRESHOLDS)
        self.weights = dict(DEFAULT_WEIGHTS)

        if config_path:
            self._load_config(config_path)

    def _load_config(self, path: Path) -> None:
        """Load scoring config from threat_lists.yaml."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
            self.dangerous_processes = config.get("dangerous_processes", self.dangerous_processes)
            self.c2_ports = config.get("c2_ports", self.c2_ports)
            self.thresholds = config.get("severity_thresholds", self.thresholds)
            self.weights = config.get("scoring_weights", self.weights)
            logger.info(f"Loaded threat lists from {path}")
        except Exception as e:
            logger.warning(f"Failed to load threat lists from {path}: {e}")

    def score(self, entry: NormalizedLogEntry, ip_activity_lookup: dict[str, int] | None = None) -> dict[str, Any]:
        """
        Score a NormalizedLogEntry using the heuristic decision tree.

        Args:
            entry: The log entry to score
            ip_activity_lookup: Optional dict of {ip: count} for historical correlation

        Returns dict with: anomaly_detected, severity, heuristic_flags,
        correlation_required, confidence, score
        """
        total_score = 0
        flags = []
        ip_lookup = ip_activity_lookup or {}

        process_name = (entry.process_name or "").lower()
        parent_process = (entry.parent_process_name or "").lower()

        # Condition 1: Dangerous process (+40)
        if any(dp.lower() in process_name for dp in self.dangerous_processes if dp):
            total_score += self.weights.get("dangerous_process", 40)
            flags.append(f"dangerous_process:{process_name}")

        # Condition 2: Web server parent + cmd/shell child (+35)
        if parent_process in WEB_SERVERS and process_name in CMD_SHELLS:
            total_score += self.weights.get("webserver_parent_cmd_child", 35)
            flags.append(f"webshell:{parent_process}->{process_name}")

        # Condition 3: C2 port (+30)
        if entry.dest_port and entry.dest_port in self.c2_ports:
            total_score += self.weights.get("c2_port", 30)
            flags.append(f"c2_port:{entry.dest_port}")

        # Condition 4: Critical event types (+50)
        if entry.event_type in (EventType.PRIVILEGE_ESCALATION, EventType.EXFILTRATION_HINT):
            weight_key = (
                "privilege_escalation_event"
                if entry.event_type == EventType.PRIVILEGE_ESCALATION
                else "exfiltration_hint_event"
            )
            total_score += self.weights.get(weight_key, 50)
            flags.append(f"critical_event:{entry.event_type.value}")

        # Condition 5: IP historical correlation (+20)
        src_seen = ip_lookup.get(entry.source_ip, 0) > 0 if entry.source_ip else False
        dst_seen = ip_lookup.get(entry.dest_ip, 0) > 0 if entry.dest_ip else False
        if src_seen or dst_seen:
            total_score += self.weights.get("ip_historical_correlation", 20)
            flags.append("ip_historical_correlation")

        # Classify severity
        severity = "BENIGN"
        correlation_required = False
        if total_score >= self.thresholds.get("P0", 61):
            severity = "P0"
            correlation_required = True
        elif total_score >= self.thresholds.get("P1", 41):
            severity = "P1"
            correlation_required = True
        elif total_score >= self.thresholds.get("P2", 21):
            severity = "P2"
            correlation_required = False

        return {
            "anomaly_detected": total_score > self.thresholds.get("P2", 21) - 1,
            "severity": severity,
            "heuristic_flags": flags,
            "correlation_required": correlation_required,
            "confidence": min(total_score / 100.0, 1.0),
            "score": total_score,
        }
