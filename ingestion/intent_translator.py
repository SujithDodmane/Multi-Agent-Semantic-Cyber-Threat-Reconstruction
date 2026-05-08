"""
AEGIS Ingestion — Synthetic Intent Translator

THIS IS THE MOST IMPORTANT IMPLEMENTATION STEP IN THE ENTIRE INGESTION PIPELINE.

Converts machine-readable canonical JSON into natural-language sentences that
BGE-m3 can embed with maximum semantic precision. Uses YAML-driven templates
with f-string interpolation. Zero machine learning.

Ref: Methodology §1.4 — "Synthetic Intent Translation — The Core Quality Mechanism"
Ref: Methodology TABLE 2 — "CRITICAL READ: The Synthetic Intent Translation mechanism
described in Section 2.4 is the single most important quality improvement available"

IMPORTANT: The synthetic_intent field is what gets embedded by BGE-m3 — NOT the JSON.
Ref: Methodology TABLE 15 Pitfall — "Always embed synthetic_intent field, never
raw_payload or the full JSON object"
"""

from __future__ import annotations

import ipaddress
import logging
import math
from collections import Counter
from pathlib import Path
from typing import Any, Optional

import yaml

from ingestion.models import EventType, NormalizedLogEntry

logger = logging.getLogger(__name__)

# ─── Default config path ────────────────────────────────────────────────────

_DEFAULT_CONFIG_PATH = Path(__file__).parent / "config" / "intent_templates.yaml"

# ─── Shannon Entropy ────────────────────────────────────────────────────────


def compute_shannon_entropy(domain: str) -> float:
    """
    Compute Shannon entropy of a domain string (stripping TLD).

    Ref: Methodology §1.4 — "The Shannon entropy of a string is computed as
    the sum over all unique characters of -(probability * log2(probability)).
    For DNS domains, compute entropy only on the hostname labels (stripping the TLD)."

    Legitimate domains: ~2.5-3.0 entropy
    DGA domains: >4.0 entropy
    Default threshold: 3.5 (configurable in intent_templates.yaml)
    """
    if not domain:
        return 0.0

    # Strip TLD: remove the last label
    parts = domain.split(".")
    if len(parts) > 1:
        hostname_part = ".".join(parts[:-1])
    else:
        hostname_part = domain

    if not hostname_part:
        return 0.0

    length = len(hostname_part)
    char_counts = Counter(hostname_part)
    entropy = 0.0

    for count in char_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


# ─── RFC 1918 Private IP Check ──────────────────────────────────────────────


def is_private_ip(ip_str: Optional[str]) -> bool:
    """Check if an IP address is in a private RFC1918 range."""
    if not ip_str:
        return False
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


# ─── SQL Keyword Detection ──────────────────────────────────────────────────

SQL_KEYWORDS = {"SELECT", "UNION", "DROP", "INSERT", "DELETE", "UPDATE", "EXEC", "EXECUTE", "--", "OR 1=1"}


def contains_sql_keywords(text: Optional[str]) -> bool:
    """Check if text contains SQL injection indicators."""
    if not text:
        return False
    upper = text.upper()
    return any(kw in upper for kw in SQL_KEYWORDS)


# ─── System Directory Detection ────────────────────────────────────────────

SYSTEM_DIRS = [
    "system32", "syswow64", "windows\\system", "/etc/", "/bin/",
    "/sbin/", "/usr/bin/", "/usr/sbin/", "c:\\windows\\",
]


def is_system_directory(path: Optional[str]) -> bool:
    """Check if a file path is in a protected system directory."""
    if not path:
        return False
    lower = path.lower().replace("\\", "/")
    return any(d.replace("\\", "/") in lower for d in SYSTEM_DIRS)


# ─── Web Server Detection ──────────────────────────────────────────────────

DEFAULT_WEB_SERVERS = [
    "apache2", "apache2.exe", "nginx", "nginx.exe",
    "w3wp.exe", "tomcat", "httpd", "httpd.exe",
]


# ─── Intent Translator Class ───────────────────────────────────────────────


class IntentTranslator:
    """
    Translates NormalizedLogEntry objects into natural-language synthetic_intent strings.

    Loads templates from YAML config. Applies enrichment conditions.
    Handles null fields gracefully with 'unknown' substitution.

    Ref: Methodology §1.4 — Complete section
    """

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or _DEFAULT_CONFIG_PATH
        self.config: dict[str, Any] = {}
        self.templates: dict[str, Any] = {}
        self.dns_entropy_threshold: float = 3.5
        self.web_server_processes: list[str] = DEFAULT_WEB_SERVERS
        self._load_config()

    def _load_config(self) -> None:
        """Load templates from YAML config file."""
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f) or {}
            self.templates = self.config.get("templates", {})
            self.dns_entropy_threshold = self.config.get("dns_entropy_threshold", 3.5)
            self.web_server_processes = self.config.get("web_server_processes", DEFAULT_WEB_SERVERS)
            logger.info(f"Loaded {len(self.templates)} intent templates from {self.config_path}")
        except FileNotFoundError:
            logger.warning(f"Intent template config not found at {self.config_path}, using defaults")
            self._load_defaults()
        except Exception as e:
            logger.error(f"Failed to load intent templates: {e}")
            self._load_defaults()

    def _load_defaults(self) -> None:
        """Fallback defaults if YAML config is unavailable."""
        self.templates = {
            EventType.UNKNOWN.value: {
                "template": "Security event of type {event_type} detected on {hostname} at {event_timestamp}. Raw event code: {event_code}.",
                "enrichments": [],
                "priority": 99,
            }
        }

    def translate(self, entry: NormalizedLogEntry) -> tuple[str, Optional[str]]:
        """
        Generate synthetic_intent string from a NormalizedLogEntry.

        Returns (synthetic_intent, mitre_technique_hint).

        Ref: Methodology §1.4 — "The translation requires zero machine learning.
        It is implemented as a Python dictionary of templates, one per log type,
        using f-string interpolation."
        """
        event_type = entry.event_type.value
        mitre_hint = entry.mitre_technique_hint

        # Route to the appropriate template handler
        if event_type == EventType.PROCESS_CREATION.value:
            return self._translate_process_creation(entry)
        elif event_type == EventType.NETWORK_CONNECTION.value:
            return self._translate_network_connection(entry)
        elif event_type in (EventType.AUTHENTICATION_FAILURE.value, EventType.AUTHENTICATION_FAILURE_BURST.value):
            return self._translate_auth_failure(entry)
        elif event_type == EventType.DNS_QUERY.value:
            return self._translate_dns_query(entry)
        elif event_type == EventType.HTTP_REQUEST.value:
            return self._translate_http_request(entry)
        elif event_type == EventType.FILE_WRITE.value:
            return self._translate_file_write(entry)
        elif event_type == EventType.PRIVILEGE_ESCALATION.value:
            return self._translate_privilege_escalation(entry)
        elif event_type == EventType.AUTHENTICATION_SUCCESS.value:
            return self._translate_auth_success(entry)
        else:
            return self._translate_fallback(entry)

    # ─── Per-Type Translation Methods ───────────────────────────────────────

    def _translate_process_creation(self, entry: NormalizedLogEntry) -> tuple[str, Optional[str]]:
        """
        Ref: Methodology §1.4 — PROCESS_CREATION template
        "User {user_account} executed {process_name} (spawned by {parent_process_name}) on {hostname}."
        """
        user = entry.get_field_safe("user_account")
        proc = entry.get_field_safe("process_name")
        parent = entry.get_field_safe("parent_process_name")
        host = entry.get_field_safe("hostname")

        intent = f"User {user} executed {proc} (spawned by {parent}) on {host}."
        mitre_hint = None

        # Enrichment: command line args
        if entry.command_line_args:
            intent += f" Command line arguments indicate {entry.command_line_args}."

        # Enrichment: web server parent → possible web shell
        if parent.lower() in [ws.lower() for ws in self.web_server_processes]:
            intent += " Parent process is a web server — possible web shell execution."
            mitre_hint = "T1505.003"

        return intent, mitre_hint

    def _translate_network_connection(self, entry: NormalizedLogEntry) -> tuple[str, Optional[str]]:
        """
        Ref: Methodology §1.4 — NETWORK_CONNECTION template
        """
        proc = entry.get_field_safe("process_name")
        host = entry.get_field_safe("hostname")
        src_ip = entry.get_field_safe("source_ip")
        src_port = entry.get_field_safe("source_port")
        dst_ip = entry.get_field_safe("dest_ip")
        dst_port = entry.get_field_safe("dest_port")

        intent = f"{proc} on {host} initiated a network connection from {src_ip}:{src_port} to {dst_ip}:{dst_port}."
        mitre_hint = None

        # Enrichment: HTTPS
        if entry.dest_port == 443:
            intent += " Connection is HTTPS-encrypted."

        # Enrichment: private destination → lateral movement
        if is_private_ip(entry.dest_ip):
            intent += " Destination is an internal host — possible lateral movement."
            mitre_hint = "T1021"

        return intent, mitre_hint

    def _translate_auth_failure(self, entry: NormalizedLogEntry) -> tuple[str, Optional[str]]:
        """
        Ref: Methodology §1.4 — AUTHENTICATION_FAILURE template
        """
        user = entry.get_field_safe("user_account")
        host = entry.get_field_safe("hostname")
        src = entry.get_field_safe("source_ip")

        intent = f"Authentication failure for user {user} on {host} from source {src}."
        # Note: burst detection (5+ failures) is handled at the queue/triage level
        return intent, None

    def _translate_dns_query(self, entry: NormalizedLogEntry) -> tuple[str, Optional[str]]:
        """
        Ref: Methodology §1.4 — DNS_QUERY template with entropy detection
        """
        host = entry.get_field_safe("hostname")
        src = entry.get_field_safe("source_ip")
        query = entry.get_field_safe("dns_query")

        intent = f"{host} ({src}) queried DNS for {query}."
        mitre_hint = None

        # Entropy-based anomaly detection
        if entry.dns_query:
            entropy = compute_shannon_entropy(entry.dns_query)
            labels = entry.dns_query.split(".")
            if entropy > self.dns_entropy_threshold or len(labels) > 4:
                intent += " Domain has high entropy — possible DNS tunneling or DGA activity."
                mitre_hint = "T1071.004"

        return intent, mitre_hint

    def _translate_http_request(self, entry: NormalizedLogEntry) -> tuple[str, Optional[str]]:
        """
        Ref: Methodology §1.4 — HTTP_REQUEST template
        """
        src = entry.get_field_safe("source_ip")
        method = entry.get_field_safe("http_method")
        url = entry.get_field_safe("http_url")
        host = entry.get_field_safe("hostname")

        intent = f"{src} made a {method} request to {url} on {host}."
        mitre_hint = None

        # SQL injection detection
        if contains_sql_keywords(entry.http_url):
            intent += " URL contains SQL syntax — possible injection attempt."

        return intent, mitre_hint

    def _translate_file_write(self, entry: NormalizedLogEntry) -> tuple[str, Optional[str]]:
        """
        Ref: Methodology §1.4 — FILE_WRITE template
        """
        proc = entry.get_field_safe("process_name")
        path = entry.get_field_safe("file_path")
        host = entry.get_field_safe("hostname")

        intent = f"{proc} wrote to file {path} on {host}."
        mitre_hint = None

        # System directory detection
        if is_system_directory(entry.file_path):
            intent += " Target is a protected system directory — possible persistence mechanism."
            mitre_hint = "T1543"

        return intent, mitre_hint

    def _translate_privilege_escalation(self, entry: NormalizedLogEntry) -> tuple[str, Optional[str]]:
        """Handle privilege escalation events (e.g., Sysmon EventID 10 = lsass access)."""
        proc = entry.get_field_safe("process_name")
        host = entry.get_field_safe("hostname")
        user = entry.get_field_safe("user_account")

        intent = f"Privilege escalation detected: {proc} performed a privileged operation on {host} as user {user}."

        # Check if lsass is accessed → credential dumping
        if entry.process_name and "lsass" in entry.process_name.lower():
            intent = f"{proc} on {host} accessed process lsass.exe — possible credential dumping."
            return intent, "T1003.001"

        return intent, "T1055"

    def _translate_auth_success(self, entry: NormalizedLogEntry) -> tuple[str, Optional[str]]:
        """Handle authentication success events."""
        user = entry.get_field_safe("user_account")
        host = entry.get_field_safe("hostname")
        src = entry.get_field_safe("source_ip")

        intent = f"Successful authentication for user {user} on {host} from {src}."
        return intent, None

    def _translate_fallback(self, entry: NormalizedLogEntry) -> tuple[str, Optional[str]]:
        """
        Fallback template for unknown/unmatched event types.

        Ref: Methodology §1.4 — "the fallback template is:
        'Security event of type {event_type} detected on {hostname} at {event_timestamp}.
        Raw event code: {event_code}.'"
        """
        etype = entry.get_field_safe("event_type")
        host = entry.get_field_safe("hostname")
        ts = entry.get_field_safe("event_timestamp")
        code = entry.get_field_safe("event_code")

        intent = f"Security event of type {etype} detected on {host} at {ts}. Raw event code: {code}."
        return intent, None


# ─── Module-level singleton ─────────────────────────────────────────────────

_default_translator: Optional[IntentTranslator] = None


def get_translator(config_path: Optional[Path] = None) -> IntentTranslator:
    """Get or create the default IntentTranslator instance."""
    global _default_translator
    if _default_translator is None or config_path is not None:
        _default_translator = IntentTranslator(config_path)
    return _default_translator


def translate_entry(entry: NormalizedLogEntry) -> NormalizedLogEntry:
    """
    Apply synthetic intent translation to a NormalizedLogEntry.
    Modifies the entry in-place and returns it.

    This is the main entry point called by the ingestion pipeline.
    """
    translator = get_translator()
    synthetic_intent, mitre_hint = translator.translate(entry)
    entry.synthetic_intent = synthetic_intent
    if mitre_hint:
        entry.mitre_technique_hint = mitre_hint
    return entry
