"""Copilot agent – interactive Q&A about the current incident.

Provides a single public function ``ask_copilot`` that formats a prompt with all
relevant incident data (alert, investigation, MITRE mapping, severity, threat
intelligence, AI analyst report) and sends it to an OpenAI‑compatible chat
completion endpoint. The implementation mirrors the pattern used in
``src.core.reasoning.ai_analyst``.
"""

from __future__ import annotations

import json
import os
import textwrap
from typing import Any, Dict, List, Optional

import httpx

# ---------------------------------------------------------------------------
# Configuration – read once at import time, same variables as used by the AI
# analyst module.
# ---------------------------------------------------------------------------
_OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
_OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
_OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
_TIMEOUT = 30.0  # seconds for the HTTP request

# ---------------------------------------------------------------------------
# Prompt template – the system message describes the role and constraints.
# ---------------------------------------------------------------------------
_SYSTEM_PROMPT = textwrap.dedent(
    """
    You are an experienced SOC analyst assistant.

    Answer questions strictly using the supplied incident data.
    If information is unavailable, say so.
    Do not invent evidence.
    Keep answers concise, technical, and actionable.
    """
)

# ---------------------------------------------------------------------------
# Helper to build the user‑message payload that contains all context.
# ---------------------------------------------------------------------------
def _build_user_prompt(
    alert: Any,
    investigation: Any,
    mitre: List[Any],
    severity_score: float,
    severity_level: str,
    threat_intel: List[Any],
    ai_report: Optional[Dict[str, Any]],
) -> str:
    """Serialize the incident artefacts into a compact JSON snippet.

    The function mirrors the approach used by ``ai_analyst`` – it creates a
    minimal JSON object that the LLM can reference without overwhelming the
    token budget.
    """
    payload: Dict[str, Any] = {
        "alert": json.loads(alert.json()) if hasattr(alert, "json") else alert,
        "investigation": json.loads(investigation.json())
        if hasattr(investigation, "json")
        else investigation,
        "mitre": [json.loads(t.json()) if hasattr(t, "json") else t for t in mitre],
        "severity": {"score": severity_score, "level": severity_level},
        "threat_intel": [json.loads(t.json()) if hasattr(t, "json") else t for t in threat_intel],
        "ai_report": ai_report or {},
    }
    # Compact representation – keep it on one line to stay within token limits.
    return json.dumps(payload, separators=(",", ":"))


def _call_openai(messages: List[Dict[str, str]]) -> Optional[str]:
    """Send a chat completion request and return the model's raw response text.

    Returns ``None`` on any error (missing key, network problem, non‑200 HTTP
    status, or JSON parsing failure). Errors are printed so that Streamlit can
    surface them in the UI.
    """
    if not _OPENAI_API_KEY:
        print("[copilot_agent] No OPENAI_API_KEY – cannot contact model.")
        return None

    headers = {"Authorization": f"Bearer {_OPENAI_API_KEY}"}
    url = f"{_OPENAI_BASE_URL.rstrip('/')}/chat/completions"
    payload = {
        "model": _OPENAI_MODEL,
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": 800,
    }
    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            resp = client.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        return content
    except Exception as exc:  # pylint: disable=broad-except
        print(f"[copilot_agent] OpenAI request failed: {exc}")
        return None


def ask_copilot(
    question: str,
    alert: Any,
    investigation: Any,
    threat_intel: List[Any],
    ai_report: Optional[Dict[str, Any]],
) -> str:
    """Answer an analyst question about the current incident.

    Parameters
    ----------
    question:
        The free‑form question typed by the analyst.
    alert, investigation, threat_intel, ai_report:
        Objects returned by the deterministic pipeline. ``threat_intel`` is a
        list of ``ThreatIntelResult`` models; ``ai_report`` is the dict produced
        by ``src.core.reasoning.ai_analyst.generate_report`` (or ``None``).

    Returns
    -------
    str
        The model's answer, or an explanatory error string if the request could
        not be completed.
    """
    # Import additional helpers lazily to avoid circular imports at module load
    from src.core.reasoning.severity_engine import calculate_severity
    from src.core.reasoning.mitre_mapper import map_to_mitre

    # Severity information – calculate_severity returns (score, level)
    severity_score, severity_level = calculate_severity(alert)
    mitre_techniques = map_to_mitre(alert)

    user_prompt = _build_user_prompt(
        alert=alert,
        investigation=investigation,
        mitre=mitre_techniques,
        severity_score=severity_score,
        severity_level=severity_level.value if hasattr(severity_level, "value") else str(severity_level),
        threat_intel=threat_intel,
        ai_report=ai_report,
    )

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": f"Question: {question}\nContext: {user_prompt}"},
    ]

    response = _call_openai(messages)
    if response is None:
        return "Unable to obtain a response – check that OPENAI_API_KEY is set and the API is reachable."
    return response

# The module exposes only ``ask_copilot``; everything else is internal.
__all__ = ["ask_copilot"]
