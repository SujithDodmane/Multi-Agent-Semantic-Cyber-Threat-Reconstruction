"""
AEGIS Unit Tests — Intent Translator & Entropy

Tests the synthetic intent translation and Shannon entropy computation.

Ref: Methodology §5.1 — "the synthetic_intent string matches the expected
template output exactly (using a known input with known field values)"
"""

import pytest

from ingestion.intent_translator import (
    IntentTranslator,
    compute_shannon_entropy,
    contains_sql_keywords,
    is_private_ip,
    is_system_directory,
    translate_entry,
)
from ingestion.models import EventType, NormalizedLogEntry


# ─── Shannon Entropy Tests ──────────────────────────────────────────────────


class TestShannonEntropy:
    """
    Ref: Methodology §1.4 — "Legitimate domain names like 'google.com' have entropy
    around 2.5–3.0. DGA-generated domains like 'xkzqwpmn.ru' have entropy above 4.0."
    """

    def test_legitimate_domain_low_entropy(self):
        """google.com should have entropy ~2.5-3.0"""
        entropy = compute_shannon_entropy("google.com")
        assert entropy < 3.5, f"Expected <3.5 for legitimate domain, got {entropy}"

    def test_dga_domain_high_entropy(self):
        """DGA-like domains should have entropy >3.5"""
        # "xkzqwpmn.ru" = 8 unique chars in 8 chars = 3.0 entropy (all unique)
        # A longer DGA domain produces higher entropy:
        entropy = compute_shannon_entropy("xkz2qwp9mn4t7b.ru")
        assert entropy > 3.5, f"Expected >3.5 for DGA domain, got {entropy}"

    def test_high_entropy_exfil_domain(self):
        """Base64-encoded subdomain should flag as high entropy"""
        entropy = compute_shannon_entropy("c29tZXNlY3JldGRhdGE.exfil.attacker.com")
        assert entropy > 3.5, f"Expected >3.5 for exfil domain, got {entropy}"

    def test_empty_domain(self):
        entropy = compute_shannon_entropy("")
        assert entropy == 0.0

    def test_single_char_domain(self):
        entropy = compute_shannon_entropy("a.com")
        assert entropy == 0.0  # Single char = zero entropy

    def test_cdn_subdomain(self):
        """CDN subdomains may have moderate entropy — should be near threshold"""
        entropy = compute_shannon_entropy("d1234abcdef.cloudfront.net")
        # These may fall near 3.5 — acceptable false positive territory
        assert entropy > 2.0


# ─── Helper Function Tests ──────────────────────────────────────────────────


class TestHelperFunctions:
    def test_private_ip_rfc1918(self):
        assert is_private_ip("10.0.0.5") is True
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("172.16.0.1") is True

    def test_public_ip(self):
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False

    def test_invalid_ip(self):
        assert is_private_ip("not_an_ip") is False
        assert is_private_ip(None) is False
        assert is_private_ip("") is False

    def test_sql_keywords_detected(self):
        assert contains_sql_keywords("SELECT * FROM users") is True
        assert contains_sql_keywords("id=1 UNION SELECT") is True
        assert contains_sql_keywords("'; DROP TABLE--") is True

    def test_sql_keywords_clean(self):
        assert contains_sql_keywords("/index.html") is False
        assert contains_sql_keywords(None) is False

    def test_system_directory(self):
        assert is_system_directory("C:\\Windows\\System32\\evil.dll") is True
        assert is_system_directory("/etc/cron.d/backdoor") is True
        assert is_system_directory("/bin/malware") is True

    def test_non_system_directory(self):
        assert is_system_directory("C:\\Users\\admin\\Desktop\\file.txt") is False
        assert is_system_directory("/home/user/file.txt") is False
        assert is_system_directory(None) is False


# ─── Intent Translation Tests ───────────────────────────────────────────────


class TestIntentTranslation:
    """
    Ref: Methodology §5.1 — "the synthetic_intent string matches the expected
    template output exactly"
    """

    def test_process_creation_basic(self):
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.PROCESS_CREATION,
            hostname="WORKSTATION01",
            sha256_hash="abc123",
            raw_payload="test",
            user_account="admin",
            process_name="cmd.exe",
            parent_process_name="explorer.exe",
        )
        entry = translate_entry(entry)
        assert "admin" in entry.synthetic_intent
        assert "cmd.exe" in entry.synthetic_intent
        assert "explorer.exe" in entry.synthetic_intent
        assert "WORKSTATION01" in entry.synthetic_intent

    def test_process_creation_web_shell(self):
        """Ref: Methodology §1.4 — web server parent → web shell detection"""
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.PROCESS_CREATION,
            hostname="WEBSERVER01",
            sha256_hash="abc123",
            raw_payload="test",
            user_account="www-data",
            process_name="cmd.exe",
            parent_process_name="apache2",
        )
        entry = translate_entry(entry)
        assert "web server" in entry.synthetic_intent.lower()
        assert "web shell" in entry.synthetic_intent.lower()
        assert entry.mitre_technique_hint == "T1505.003"

    def test_network_connection_internal(self):
        """Ref: Methodology §1.4 — private dest_ip → lateral movement"""
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.NETWORK_CONNECTION,
            hostname="WORKSTATION01",
            sha256_hash="abc123",
            raw_payload="test",
            process_name="powershell.exe",
            source_ip="10.0.0.5",
            source_port=49152,
            dest_ip="10.0.0.10",
            dest_port=445,
        )
        entry = translate_entry(entry)
        assert "powershell.exe" in entry.synthetic_intent
        assert "10.0.0.10" in entry.synthetic_intent
        assert "lateral movement" in entry.synthetic_intent.lower()
        assert entry.mitre_technique_hint == "T1021"

    def test_network_connection_https(self):
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.NETWORK_CONNECTION,
            hostname="WORKSTATION01",
            sha256_hash="abc123",
            raw_payload="test",
            process_name="chrome.exe",
            source_ip="10.0.0.5",
            dest_ip="142.250.80.46",
            dest_port=443,
        )
        entry = translate_entry(entry)
        assert "HTTPS" in entry.synthetic_intent

    def test_dns_query_high_entropy(self):
        """Ref: Methodology §1.4 — high entropy DNS → tunneling detection"""
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.DNS_QUERY,
            hostname="WORKSTATION05",
            sha256_hash="abc123",
            raw_payload="test",
            source_ip="10.1.1.50",
            dns_query="c29tZXNlY3JldGRhdGE.exfil.attacker.com",
        )
        entry = translate_entry(entry)
        assert "high entropy" in entry.synthetic_intent.lower()
        assert "DNS tunneling" in entry.synthetic_intent or "DGA" in entry.synthetic_intent
        assert entry.mitre_technique_hint == "T1071.004"

    def test_dns_query_legitimate(self):
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.DNS_QUERY,
            hostname="WORKSTATION01",
            sha256_hash="abc123",
            raw_payload="test",
            source_ip="10.0.0.5",
            dns_query="www.google.com",
        )
        entry = translate_entry(entry)
        assert "high entropy" not in entry.synthetic_intent.lower()

    def test_auth_failure(self):
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.AUTHENTICATION_FAILURE,
            hostname="DC01",
            sha256_hash="abc123",
            raw_payload="test",
            user_account="admin",
            source_ip="192.168.1.100",
        )
        entry = translate_entry(entry)
        assert "Authentication failure" in entry.synthetic_intent
        assert "admin" in entry.synthetic_intent

    def test_http_request_sql_injection(self):
        """Ref: Methodology §1.4 — SQL keywords in URL"""
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.HTTP_REQUEST,
            hostname="WEBSERVER01",
            sha256_hash="abc123",
            raw_payload="test",
            source_ip="attacker.ip",
            http_method="GET",
            http_url="/page?id=1 UNION SELECT * FROM users",
        )
        entry = translate_entry(entry)
        assert "SQL syntax" in entry.synthetic_intent

    def test_file_write_system_dir(self):
        """Ref: Methodology §1.4 — system directory → persistence"""
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.FILE_WRITE,
            hostname="TARGET01",
            sha256_hash="abc123",
            raw_payload="test",
            process_name="malware.exe",
            file_path="C:\\Windows\\System32\\evil.dll",
        )
        entry = translate_entry(entry)
        assert "system directory" in entry.synthetic_intent.lower()
        assert entry.mitre_technique_hint == "T1543"

    def test_fallback_unknown(self):
        """Ref: Methodology §1.4 — fallback template for UNKNOWN"""
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.UNKNOWN,
            hostname="SERVER01",
            sha256_hash="abc123",
            raw_payload="test",
            event_code="9999",
        )
        entry = translate_entry(entry)
        assert "Security event" in entry.synthetic_intent
        assert "SERVER01" in entry.synthetic_intent
        assert "9999" in entry.synthetic_intent

    def test_null_field_substitution(self):
        """
        Ref: Methodology §1.4 — "template renderer must substitute null fields
        with the string 'unknown'"
        """
        entry = NormalizedLogEntry(
            event_timestamp="2026-05-07T10:00:00Z",
            event_type=EventType.PROCESS_CREATION,
            hostname="WORKSTATION01",
            sha256_hash="abc123",
            raw_payload="test",
            # user_account, process_name, parent_process_name are all None
        )
        entry = translate_entry(entry)
        assert "unknown" in entry.synthetic_intent.lower()
        # Must not crash — this is the key requirement
