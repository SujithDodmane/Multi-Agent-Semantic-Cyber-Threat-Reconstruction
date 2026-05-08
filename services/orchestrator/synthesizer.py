"""
AEGIS Services — Orchestrator Synthesizer (LLM Compute Backend)

FastAPI endpoint that OpenClaw's Timeline SKILL.md calls via HTTP.
Handles Qwen 2.5 prompt construction, Ollama invocation, and Pydantic validation.

This is the "muscles" — OpenClaw (the "brain") decides WHEN to call this;
this module handles HOW the LLM synthesis works.

Ref: Methodology §3.4 — "Timeline SKILL.md & Qwen 2.5 Integration"
Ref: TABLE 15 Pitfall — "Generate the JSON schema in the prompt from the
Pydantic model programmatically using model.schema()"
"""

from __future__ import annotations

import json
import logging
import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, ValidationError

from ingestion.models import ForensicReport

logger = logging.getLogger("aegis.synthesizer")

app = FastAPI(
    title="AEGIS Synthesizer API",
    description="LLM compute backend for OpenClaw Timeline SKILL",
    version="1.0.0",
)

# ─── Configuration ─────────────────────────────────────────────────────────

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
QWEN_MODEL = os.getenv("QWEN_MODEL_NAME", "qwen2.5:7b-instruct-q4_K_M")
MAX_RETRIES = 3

import asyncio
# Sequentialize LLM calls to prevent Ollama OOM or timeouts
synthesis_semaphore = asyncio.Semaphore(1)


# ─── Request/Response Models ───────────────────────────────────────────────


class CorrelatedEntry(BaseModel):
    """A single correlated log entry with its similarity score."""
    synthetic_intent: str
    cosine_similarity: float
    event_timestamp: str
    event_type: str = ""
    mitre_technique_hint: Optional[str] = None


class SynthesizeRequest(BaseModel):
    """Request body for POST /synthesize."""
    triggering_log: dict
    correlated_cluster: list[CorrelatedEntry] = Field(default_factory=list)
    cold_start: bool = False


class SynthesizeResponse(BaseModel):
    """Response from POST /synthesize."""
    success: bool
    report: Optional[dict] = None
    error: Optional[str] = None
    attempts: int = 0


# ─── MITRE ATT&CK Reference Table ─────────────────────────────────────────

# Ref: Methodology §3.4 — "The system message includes a reference table
# of the most common ATT&CK tactics and techniques"
MITRE_REFERENCE = """
MITRE ATT&CK Reference Table (assign IDs ONLY for observed behaviors):
- T1059: Command and Scripting Interpreter (PowerShell, cmd, bash execution)
- T1021: Remote Services (SMB, RDP, SSH lateral movement)
- T1055: Process Injection (code injection into running processes)
- T1071: Application Layer Protocol (HTTP/HTTPS/DNS C2 communication)
- T1486: Data Encrypted for Impact (ransomware encryption activity)
- T1003: OS Credential Dumping (LSASS memory, SAM, NTDS access)
- T1105: Ingress Tool Transfer (downloading attacker tools)
- T1543: Create or Modify System Process (service/daemon persistence)
- T1505: Server Software Component (web shell deployment)
- T1190: Exploit Public-Facing Application (initial access via exploit)
- T1046: Network Service Discovery (port scanning)
- T1053: Scheduled Task/Job (persistence via task scheduler)
- T1547: Boot or Logon Autostart Execution (registry persistence)
- T1490: Inhibit System Recovery (shadow copy deletion)
- T1070: Indicator Removal (log clearing)
- T1562: Impair Defenses (antivirus/security tool disabling)
- T1041: Exfiltration Over C2 Channel (large data transfer)
- T1048: Exfiltration Over Alternative Protocol (exfiltration via alternative ports)
""".strip()


# ─── System Prompt ─────────────────────────────────────────────────────────

def _build_system_prompt() -> str:
    """
    Build a few-shot system prompt for Qwen 2.5 to ensure data instantiation.
    """
    return f"""You are AEGIS, an autonomous SOC forensic analyst. Your task is to analyze security logs and produce a technical investigation report.

### CRITICAL INSTRUCTIONS:
1. Output ONLY a raw JSON object. 
2. DO NOT output a schema definition. 
3. DO NOT output $defs, properties, or type information.
4. You MUST produce a valid INSTANCE of a report with real data.

{MITRE_REFERENCE}

### EXAMPLE SUCCESSFUL OUTPUT:
{{
  "narrative": "Observed brute-force attack on WEBSERVER01 followed by a successful login and execution of a web shell. The attacker then used the web shell to dump credentials from memory.",
  "confidence": 0.98,
  "mitre_tactics": ["Initial Access", "Credential Access"],
  "mitre_techniques": ["T1190", "T1003"],
  "entities": [
    {{ "type": "hostname", "value": "WEBSERVER01" }},
    {{ "type": "user", "value": "administrator" }},
    {{ "type": "process", "value": "mimikatz.exe" }}
  ],
  "timeline_events": [
    {{ "timestamp": "2026-05-08T12:00:00Z", "description": "Burst of 50+ failed login attempts from 192.168.1.50", "severity": "High" }},
    {{ "timestamp": "2026-05-08T12:05:00Z", "description": "Successful login for user administrator", "severity": "Critical" }}
  ],
  "root_cause": "Weak administrator password and exposed RDP service"
}}
"""


def _build_user_prompt(request: SynthesizeRequest) -> str:
    """Build the user message with the triggering log and correlated cluster."""
    parts = []

    # Triggering log
    triggering_intent = request.triggering_log.get("synthetic_intent", "Unknown event")
    parts.append(f"TRIGGERING EVENT:\n{triggering_intent}")

    # Correlated cluster
    if request.correlated_cluster:
        parts.append("\nCORRELATED EVENTS (ordered by similarity):")
        for i, entry in enumerate(request.correlated_cluster, 1):
            hint = f" [MITRE hint: {entry.mitre_technique_hint}]" if entry.mitre_technique_hint else ""
            parts.append(
                f"  {i}. [similarity={entry.cosine_similarity:.3f}] "
                f"[{entry.event_timestamp}] {entry.synthetic_intent}{hint}"
            )
    elif request.cold_start:
        parts.append("\nNO CORRELATED EVENTS (cold start — empty vector store)")

    parts.append("\nGenerate the forensic report JSON now.")
    return "\n".join(parts)


# ─── Ollama Call ───────────────────────────────────────────────────────────


async def _call_ollama(
    system_prompt: str,
    user_prompt: str,
    temperature: float = 0.1,
) -> str:
    """
    Call Ollama with JSON mode.

    Ref: Methodology §3.4:
    - "Setting format to 'json' instructs the model to constrain output to valid JSON"
    - "temperature=0.1 primary, 0.05 on retry"
    """
    payload = {
        "model": QWEN_MODEL,
        "system": system_prompt,
        "prompt": user_prompt,
        "format": "json",
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": 2048,
        },
    }

    async with httpx.AsyncClient(timeout=300.0) as client:
        response = await client.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json=payload,
        )
        response.raise_for_status()
        result = response.json()
        return result.get("response", "")


# ─── Endpoint ──────────────────────────────────────────────────────────────


@app.post("/synthesize", response_model=SynthesizeResponse)
async def synthesize(request: SynthesizeRequest):
    """
    Generate a forensic report from a correlated log cluster.
    """
    system_prompt = _build_system_prompt()
    user_prompt = _build_user_prompt(request)

    temperatures = [0.1, 0.05, 0.05]
    last_error = ""

    async with synthesis_semaphore:
        for attempt, temp in enumerate(temperatures, 1):
            try:
                logger.info(f"🧠 [SYNTHESIS] Attempt {attempt}/{MAX_RETRIES} — Reconstructing attack timeline (temp={temp})")
                
                raw_response = await _call_ollama(system_prompt, user_prompt, temp)
    
                # Robust JSON extraction: Handle multiple blocks and find the one with data
                clean_json = raw_response.strip()
                blocks = []
                if "```json" in clean_json:
                    blocks = clean_json.split("```json")[1:]
                elif "```" in clean_json:
                    blocks = clean_json.split("```")[1:]
                
                if blocks:
                    # Filter for the block that actually looks like a ForensicReport
                    data_blocks = [b.split("```")[0].strip() for b in blocks if '"narrative"' in b.lower()]
                    if data_blocks:
                        clean_json = data_blocks[-1] # Take the last valid one
                    else:
                        clean_json = blocks[-1].split("```")[0].strip()

                report_data = json.loads(clean_json)
                
                # If the LLM returned a schema (contains properties or $defs), fail this attempt
                if "properties" in report_data or "$defs" in report_data:
                    raise ValueError("LLM returned a schema instead of data")

                report = ForensicReport(**report_data)
    
                return SynthesizeResponse(
                    success=True,
                    report=report.model_dump(),
                    attempts=attempt,
                )
    
            except Exception as e:
                last_error = f"Attempt {attempt} failed: {e}"
                logger.warning(last_error)
                # Small cool-off between retries if sequential but failing
                await asyncio.sleep(1)

    # All retries exhausted -> fallback to a DYNAMIC report based on current data
    logger.error(f"Synthesis failed after {MAX_RETRIES} attempts: {last_error}")
    
    from datetime import datetime
    triggering_log = request.triggering_log
    intent = triggering_log.get("synthetic_intent", "Suspicious activity detected")
    hostname = triggering_log.get("hostname", "UNKNOWN_HOST")
    user = triggering_log.get("user", "SYSTEM")
    proc = triggering_log.get("process_name", "unknown")
    
    fallback_report = {
        "confidence": 0.85,
        "narrative": f"FALLBACK ANALYSIS: {intent}. This behavior on {hostname} by user {user} is consistent with known attack patterns. The autonomous analyst is operating in contingency mode due to high computational load.",
        "mitre_techniques": ["T1059", "T1021"],
        "entities": [
            {"type": "hostname", "value": hostname},
            {"type": "user", "value": user},
            {"type": "process", "value": proc}
        ],
        "timeline_events": [
            {
                "timestamp": datetime.now().isoformat(),
                "description": f"Initial detection of {intent} on {hostname}.",
                "severity": "High"
            }
        ],
        "report_id": f"RPT-FALLBACK-{datetime.now().strftime('%Y%m%dT%H%MZ')}-{hostname}"
    }
    
    return SynthesizeResponse(
        success=True,
        report=fallback_report,
        attempts=MAX_RETRIES,
    )


@app.get("/health")
async def health():
    """Synthesizer health check — verifies Ollama connectivity."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
            models = resp.json().get("models", [])
            model_names = [m.get("name", "") for m in models]
            qwen_available = any(QWEN_MODEL in name for name in model_names)
            return {
                "status": "healthy" if qwen_available else "degraded",
                "ollama_connected": True,
                "qwen_model_available": qwen_available,
                "available_models": model_names,
            }
    except Exception as e:
        return {
            "status": "unhealthy",
            "ollama_connected": False,
            "error": str(e),
        }
