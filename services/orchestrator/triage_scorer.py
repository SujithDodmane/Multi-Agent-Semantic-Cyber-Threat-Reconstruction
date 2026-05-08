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

DEFAULT_C2_PORTS = [4444, 5555, 1337, 8888, 9001, 6666, 6667, 31337, 12345, 8443, 4443, 2222]

DEFAULT_C2_IPS = ["185.220.101.45", "185.220.101.46", "91.92.248.55", "203.0.113.77"]

DEFAULT_BAD_HASHES = ["61C0810A23580CF492A6BA4F7654566108331E7A4134C968C2D6A05261B2D8A1"]

DEFAULT_THRESHOLDS = {"P0": 61, "P1": 41, "P2": 21, "BENIGN": 0}

DEFAULT_WEIGHTS = {
    "dangerous_process": 40,
    "webserver_parent_cmd_child": 35,
    "c2_port": 30,
    "privilege_escalation_event": 50,
    "exfiltration_hint_event": 50,
    "ip_historical_correlation": 20,
    "lsass_access": 50,
    "encoded_powershell": 35,
    "log_clearing": 60,
    "shadow_delete": 60,
    "known_bad_hash": 45,
    "large_data_transfer": 40,
    "port_scan_detected": 30,
    "known_c2_ip": 50,
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
        self.c2_ips = list(DEFAULT_C2_IPS)
        self.bad_hashes = list(DEFAULT_BAD_HASHES)
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
            self.c2_ips = config.get("known_c2_ips", self.c2_ips)
            self.bad_hashes = config.get("known_bad_hashes", self.bad_hashes)
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

        # Condition 6: LSASS access (+50)
        cmd_lower = (entry.command_line_args or "").lower()
        if entry.event_type == EventType.PRIVILEGE_ESCALATION and "lsass" in cmd_lower:
            total_score += self.weights.get("lsass_access", 50)
            flags.append("lsass_access")
            
        # Condition 7: Encoded PowerShell command (+35)
        if "powershell" in process_name and ("-enc" in cmd_lower or "-encodedcommand" in cmd_lower):
            total_score += self.weights.get("encoded_powershell", 35)
            flags.append("encoded_powershell")
            
        # Condition 8: Log clearing (+60)
        if entry.event_type == EventType.EXFILTRATION_HINT and ("wevtutil" in process_name or entry.event_code in ["1102", "104"]):
            total_score += self.weights.get("log_clearing", 60)
            flags.append("log_clearing")
            
        # Condition 9: Shadow copy deletion (+60)
        if "vssadmin" in cmd_lower and "delete" in cmd_lower:
            total_score += self.weights.get("shadow_delete", 60)
            flags.append("shadow_delete")
            
        # Condition 10: Known bad process hash (+45)
        raw_payload = (entry.raw_payload or "").upper()
        if any(h.upper() in raw_payload for h in self.bad_hashes):
            total_score += self.weights.get("known_bad_hash", 45)
            flags.append("known_bad_hash")
            
        # Condition 11: Large data transfer (+40)
        bytes_out = getattr(entry, "bytes_sent", 0) or 0
        if bytes_out > 10485760:
            total_score += self.weights.get("large_data_transfer", 40)
            flags.append("large_data_transfer")
            
        # Condition 12: Port scan detected (+30)
        # Port scan logic in python relies on cognitive RAM lookup
        if entry.source_ip:
            scan_count = ip_lookup.get(f"portscan:{entry.source_ip}", 0)
            if scan_count >= 15:
                total_score += self.weights.get("port_scan_detected", 30)
                flags.append("port_scan_detected")

        # Condition 13: Known C2 IP (+50)
        if (entry.source_ip and entry.source_ip in self.c2_ips) or (entry.dest_ip and entry.dest_ip in self.c2_ips):
            total_score += self.weights.get("known_c2_ip", 50)
            flags.append("known_c2_ip")

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
