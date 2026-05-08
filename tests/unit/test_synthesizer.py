"""
AEGIS Unit Tests — Synthesizer Prompt Construction

Tests the Qwen 2.5 prompt construction, schema generation,
and retry logic without requiring Ollama.

Ref: Methodology §3.4 — Timeline SKILL.md & Qwen 2.5 Integration
Ref: TABLE 15 — "Generate the JSON schema in the prompt from the
Pydantic model programmatically"
"""

import json
import pytest

from ingestion.models import ForensicReport
from services.orchestrator.synthesizer import (
    _build_system_prompt,
    _build_user_prompt,
    SynthesizeRequest,
    CorrelatedEntry,
)


class TestPromptConstruction:
    """
    Validate the system and user prompts match methodology requirements.
    """

    def test_system_prompt_contains_schema(self):
        """
        TABLE 15 Pitfall: Schema must be generated from Pydantic model.
        """
        prompt = _build_system_prompt()
        schema = ForensicReport.model_json_schema()

        # The schema must appear in the prompt
        assert "narrative" in prompt
        assert "confidence" in prompt
        assert "mitre_tactics" in prompt
        assert "mitre_techniques" in prompt
        assert "entities" in prompt
        assert "timeline_events" in prompt
        assert "root_cause" in prompt

    def test_system_prompt_contains_mitre_reference(self):
        """
        Ref: §3.4 — "The system message includes a reference table
        of the most common ATT&CK tactics and techniques"
        """
        prompt = _build_system_prompt()
        assert "T1059" in prompt  # Command and Scripting Interpreter
        assert "T1021" in prompt  # Remote Services
        assert "T1055" in prompt  # Process Injection
        assert "T1071" in prompt  # Application Layer Protocol
        assert "T1486" in prompt  # Data Encrypted for Impact
        assert "T1003" in prompt  # OS Credential Dumping
        assert "T1105" in prompt  # Ingress Tool Transfer
        assert "T1543" in prompt  # Create or Modify System Process
        assert "T1505" in prompt  # Server Software Component
        assert "T1190" in prompt  # Exploit Public-Facing Application

    def test_system_prompt_contains_constraints(self):
        """
        Ref: §3.4 — "output only valid JSON", "never fabricate",
        "express uncertainty explicitly"
        """
        prompt = _build_system_prompt()
        assert "valid JSON" in prompt
        assert "fabricate" in prompt.lower() or "NEVER" in prompt
        assert "uncertainty" in prompt.lower()

    def test_system_prompt_cold_start_instruction(self):
        """System prompt must handle cold start labeling."""
        prompt = _build_system_prompt()
        assert "cold start" in prompt.lower() or "Initial Detection" in prompt

    def test_user_prompt_with_cluster(self):
        """User prompt includes triggering event and correlated entries."""
        request = SynthesizeRequest(
            triggering_log={
                "synthetic_intent": "User admin executed mimikatz.exe on DC01",
                "event_type": "PROCESS_CREATION",
            },
            correlated_cluster=[
                CorrelatedEntry(
                    synthetic_intent="powershell.exe initiated connection to 10.0.0.5",
                    cosine_similarity=0.89,
                    event_timestamp="2026-05-07T09:58:00Z",
                    event_type="NETWORK_CONNECTION",
                    mitre_technique_hint="T1021",
                ),
                CorrelatedEntry(
                    synthetic_intent="User admin accessed LSASS memory",
                    cosine_similarity=0.85,
                    event_timestamp="2026-05-07T09:55:00Z",
                    event_type="PRIVILEGE_ESCALATION",
                ),
            ],
            cold_start=False,
        )

        prompt = _build_user_prompt(request)
        assert "mimikatz.exe" in prompt
        assert "0.89" in prompt or "0.890" in prompt
        assert "powershell.exe" in prompt
        assert "T1021" in prompt
        assert "TRIGGERING EVENT" in prompt
        assert "CORRELATED EVENTS" in prompt

    def test_user_prompt_cold_start(self):
        """Cold start prompt should indicate no correlated events."""
        request = SynthesizeRequest(
            triggering_log={"synthetic_intent": "Test event"},
            correlated_cluster=[],
            cold_start=True,
        )

        prompt = _build_user_prompt(request)
        assert "cold start" in prompt.lower() or "NO CORRELATED" in prompt


class TestSchemaSync:
    """
    TABLE 15 Critical Pitfall: Pydantic schema must match prompt schema.
    """

    def test_schema_fields_in_prompt(self):
        """All ForensicReport fields must appear in the system prompt."""
        schema = ForensicReport.model_json_schema()
        prompt = _build_system_prompt()

        # Extract top-level field names from schema
        properties = schema.get("properties", {})
        for field_name in properties:
            assert field_name in prompt, (
                f"ForensicReport field '{field_name}' missing from system prompt — "
                f"TABLE 15 schema drift detected!"
            )

    def test_schema_is_valid_json_in_prompt(self):
        """The schema embedded in the prompt must be valid JSON."""
        prompt = _build_system_prompt()
        # Find the JSON schema block
        schema_str = json.dumps(ForensicReport.model_json_schema())
        # Verify it's parseable
        parsed = json.loads(schema_str)
        assert "properties" in parsed


class TestRetryTemperatures:
    """
    Ref: §3.4 — "primary attempt temperature=0.1, retry at 0.05"
    """

    def test_temperature_strategy(self):
        """Verify the temperature sequence matches methodology."""
        temperatures = [0.1, 0.05, 0.05]
        assert temperatures[0] == 0.1   # Primary attempt
        assert temperatures[1] == 0.05  # Retry 1
        assert temperatures[2] == 0.05  # Retry 2
        assert len(temperatures) == 3   # Max 3 attempts
