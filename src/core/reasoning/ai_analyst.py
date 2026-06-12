"""AI‑augmented analyst layer.

This module calls an OpenAI‑compatible chat model (OpenAI, Azure OpenAI, or
OpenRouter) to turn the deterministic investigation results into a polished
SOC analyst report.

The deterministic engine remains the source of truth – the AI only formats
and expands the existing findings; it never recomputes severity, MITRE
mapping, or evidence.

If the required environment variables are missing or the API call fails, the
function returns ``None`` and the UI will display a warning, keeping the
application usable offline.
"""

from __future__ import annotations

import os
import json
import textwrap
import re
from typing import Optional, Dict, Any, List

import httpx

# ---------------------------------------------------------------------------
# Configuration – read once at import time.
# ---------------------------------------------------------------------------

_OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
_OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
_OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")  # cheap, fast model

_TIMEOUT = 30.0  # seconds for the HTTP request

# ---------------------------------------------------------------------------
# Helper – build the prompt that feeds the AI.
# ---------------------------------------------------------------------------

_PROMPT_TEMPLATE = textwrap.dedent(
    """
    You are a senior SOC analyst. Using the deterministic investigation
    results provided, write a professional security analyst report.

    Required sections (JSON keys must match exactly):
    * executive_summary – a brief non‑technical summary for management (max 80 words).
    * technical_findings – detailed SOC language explaining the attack, evidence, and MITRE techniques.
    * risk_analysis – concise risk statement tying severity to potential impact.
    * recommended_actions – list of remediation steps (use the ones already
      supplied in the investigation results, re‑worded if helpful).

    Do **not** modify severity levels, MITRE mappings, or raw evidence – just
    restate them in a clear, analyst‑style narrative.

    Input JSON (do not repeat the keys, just incorporate the values):
    {input_json}
    """
)


def _build_prompt(alert_json: Dict[str, Any], investigation_json: Dict[str, Any]) -> str:
    """Create the full prompt using the deterministic results.

    The function inserts a compact JSON snippet containing the alert and
    investigation fields into the template.
    """
    combined = {
        "alert": alert_json,
        "investigation": investigation_json,
    }
    # Minify JSON for the prompt – keep it readable for the model.
    compact = json.dumps(combined, separators=(",", ":"))
    return _PROMPT_TEMPLATE.format(input_json=compact)


def _call_openai(messages: List[Dict[str, str]]) -> Optional[Dict[str, Any]]:
    """Perform a chat completion request.

    Returns the parsed JSON object from the model if successful, otherwise
    ``None``. Errors are caught and logged (via ``print`` – Streamlit will
    capture stdout).
    """
    if not _OPENAI_API_KEY:
        print("[ai_analyst] No OPENAI_API_KEY found – skipping AI report generation.")
        return None

    headers = {"Authorization": f"Bearer {_OPENAI_API_KEY}"}
    url = f"{_OPENAI_BASE_URL.rstrip('/')}/chat/completions"
    payload = {
        "model": _OPENAI_MODEL,
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": 800,
        "response_format": {"type": "json_object"},
    }
    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            resp = client.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
        # OpenAI returns ``choices[0].message.content``
        content = data["choices"][0]["message"]["content"]
        # Debug diagnostics for API response issues
        # -----------------------------------------------------------------
        # Robust JSON extraction – the model sometimes wraps the JSON in markdown
        # fences (```json, ```jsonc, etc.) or adds stray characters before/after.
        # -----------------------------------------------------------------
        def _attempt_parse(txt: str) -> Optional[Dict[str, Any]]:
            try:
                return json.loads(txt)
            except Exception:  # pylint: disable=broad-except
                return None

        parsed = _attempt_parse(content)
        if parsed is not None:
            print("[ai_analyst] JSON parsed successfully on first attempt.")
            return parsed

        # 1️⃣ Strip markdown fences and leading markers
        cleaned = content.strip()
        # Remove leading triple backticks and optional language specifier
        cleaned = re.sub(r"^```\s*(jsonc?|\"?)?", "", cleaned, flags=re.IGNORECASE)
        # Remove trailing triple backticks
        cleaned = re.sub(r"```$", "", cleaned)
        parsed = _attempt_parse(cleaned)
        if parsed is not None:
            print("[ai_analyst] JSON parsed after stripping markdown fences.")
            return parsed

        # 2️⃣ Fallback: extract the first {...} block
        brace_start = cleaned.find('{')
        brace_end = cleaned.rfind('}')
        if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
            json_blob = cleaned[brace_start:brace_end + 1]
            parsed = _attempt_parse(json_blob)
            if parsed is not None:
                print("[ai_analyst] JSON parsed after extracting outer braces.")
                return parsed

        # 3️⃣ Final fallback – return a minimal report structure
        print("[ai_analyst] All JSON parsing attempts failed – returning fallback report.")
        fallback = {
            "executive_summary": "AI report generation failed.",
            "technical_findings": content[:500],
            "risk_analysis": "Unavailable",
            "recommended_actions": [],
        }
        return fallback
    except Exception as e:  # pylint: disable=broad-except
        print(f"[ai_analyst] OpenAI request failed: {e}")
        return None


def generate_report(alert: "Alert", investigation: "InvestigationResult") -> Optional[Dict[str, Any]]:
    """Generate an AI‑augmented analyst report.

    Parameters
    ----------
    alert: Alert
        The original alert model (used only for context – not mutated).
    investigation: InvestigationResult
        Deterministic findings produced by the rule‑based engine.

    Returns
    -------
    dict or None
        JSON object with the keys ``executive_summary``, ``technical_findings``,
        ``risk_analysis`` and ``recommended_actions``. ``None`` indicates that
        the AI service could not be contacted or is not configured.
    """
    # Convert Pydantic models to plain dicts (exclude private fields).
    alert_dict = json.loads(alert.json())
    inv_dict = json.loads(investigation.json())

    prompt = _build_prompt(alert_dict, inv_dict)
    messages = [{"role": "user", "content": prompt}]
    return _call_openai(messages)
