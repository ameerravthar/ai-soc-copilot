"""Deterministic Investigation Agent for the MVP.

The agent ties together the earlier components (severity engine,
MITRE mapper, and rule‑based attack classification) and produces a
structured :class:`~src.core.models.investigation.InvestigationResult`.

All logic is fully deterministic – no external LLM calls – making the
behaviour repeatable for the hackathon demo while keeping the codebase
easy to extend later (e.g., by swapping in an LLM‑backed implementation).
"""

from __future__ import annotations

from typing import List

from ..models.alert import Alert
from ..models.investigation import InvestigationResult
from ..models.severity import SeverityLevel
from .severity_engine import calculate_severity
from .mitre_mapper import map_to_mitre

# ---------------------------------------------------------------------------
# Helper data – simple rule tables that can be expanded later.
# ---------------------------------------------------------------------------

# Mapping from ``event_type`` to a higher‑level attack description.
_ATTACK_TYPE_MAP = {
    "ssh_bruteforce": "Brute Force Attack",
    "port_scan": "Network Reconnaissance",
    "malware_detection": "Malware Execution",
    "suspicious_login": "Valid Accounts Abuse",
    "privilege_escalation": "Privilege Escalation",
    "data_exfiltration": "Data Exfiltration",
    "ransomware": "Ransomware Activity",
}

# Human‑readable evidence templates per ``event_type``.
_EVIDENCE_TEMPLATES = {
    "ssh_bruteforce": [
        "Multiple failed SSH authentication attempts were detected.",
        "External host {source_ip} targeted internal host {dest_ip}.",
        "The {username} account was targeted.",
        "Activity is consistent with credential brute‑force behavior.",
    ],
    "port_scan": [
        "Port scanning activity was observed from {source_ip} against {dest_ip}.",
        "Multiple ports were probed, indicating reconnaissance.",
    ],
    "malware_detection": [
        "Malicious executable signatures were detected on host {dest_ip}.",
        "Source IP {source_ip} delivered the payload.",
    ],
    "suspicious_login": [
        "A login from {source_ip} to {dest_ip} matched a known suspicious pattern.",
        "The user account used appears legitimate but the source is unexpected.",
    ],
    "privilege_escalation": [
        "Privilege escalation command observed on {dest_ip}.",
        "User {username} attempted to gain higher privileges.",
    ],
    "data_exfiltration": [
        "Large amount of data transferred from {dest_ip} to external IP {source_ip}.",
        "Transfer matches known exfiltration techniques.",
    ],
    "ransomware": [
        "Ransomware encryption activity detected on {dest_ip}.",
        "Encryption files match known ransomware patterns.",
    ],
}

# Generic remediation catalogue – keyed by the high‑level attack type.
_REMEDIATION_CATALOG = {
    "Brute Force Attack": [
        "Block source IP at firewall.",
        "Enforce account lockout after repeated failures.",
        "Enable multi‑factor authentication.",
    ],
    "Network Reconnaissance": [
        "Rate‑limit connection attempts from the source IP.",
        "Alert on repeated scans across multiple ports.",
    ],
    "Malware Execution": [
        "Quarantine the host.",
        "Run anti‑malware signatures.",
        "Isolate affected network segment.",
    ],
    "Valid Accounts Abuse": [
        "Review recent successful logins from the source.",
        "Force password reset for the affected account.",
    ],
    "Privilege Escalation": [
        "Audit recent sudo / admin changes.",
        "Revoke excessive privileges.",
    ],
    "Data Exfiltration": [
        "Inspect outbound traffic logs.",
        "Block exfiltration destination IPs.",
        "Alert on large data transfers.",
    ],
    "Ransomware Activity": [
        "Isolate affected endpoints immediately.",
        "Restore from latest backup.",
        "Engage incident response team.",
    ],
    "Unknown": ["Investigate manually – no predefined remediation."]
}


def _extract_evidence(alert: Alert) -> List[str]:
    """Generate analyst‑style evidence statements for *alert*.

    Uses predefined sentence templates when available; otherwise falls back
    to a generic key‑value list.
    """
    templates = _EVIDENCE_TEMPLATES.get(alert.event_type)
    if templates:
        # Fill placeholders from alert fields; unknown placeholders are left as‑is.
        filled = []
        for tmpl in templates:
            try:
                filled.append(tmpl.format(**alert.raw))
            except KeyError:
                # If a specific placeholder is missing, ignore it.
                filled.append(tmpl)
        return filled
    # Generic fallback – list key/value pairs.
    return [f"{k} = {v}" for k, v in alert.raw.items()]


def _severity_reasoning(alert: Alert, score: int, level: SeverityLevel) -> str:
    """Return an analyst‑style explanation for the severity decision.
    """
    base_score = {
        "ssh_bruteforce": 65,
        "port_scan": 40,
        "malware_detection": 80,
        "suspicious_login": 55,
        "privilege_escalation": 85,
        "data_exfiltration": 90,
        "ransomware": 95,
    }.get(alert.event_type, 30)
    reasoning = (
        f"Severity was classified as {level.value} because the base score for "
        f"'{alert.event_type}' is {base_score}, "
        f"adjusted to {score} after considering source and destination context."
    )
    return reasoning


def _risk_assessment(severity: SeverityLevel) -> str:
    """Return a richer risk description based on *severity*.
    """
    mapping = {
        SeverityLevel.LOW: "Limited suspicious activity observed. Continued monitoring recommended.",
        SeverityLevel.MEDIUM: "Attack activity may indicate an attempted compromise and warrants investigation.",
        SeverityLevel.HIGH: "Evidence suggests a significant threat with elevated risk to system security.",
        SeverityLevel.CRITICAL: "Indicators strongly suggest active compromise or unauthorized access.",
    }
    return mapping.get(severity, "Risk level unknown.")


def investigate(alert: Alert) -> InvestigationResult:
    """Run the deterministic investigation pipeline.

    1️⃣ Attack classification – map ``event_type`` to a friendly attack description.
    2️⃣ Evidence collection – produce analyst‑style observations.
    3️⃣ Severity calculation – reuse the existing rule‑based engine.
    4️⃣ Severity reasoning – explain the chosen level in SOC language.
    5️⃣ Risk assessment – concise risk statement.
    6️⃣ Recommendations – lookup actions based on attack type.
    The function returns an :class:`InvestigationResult` ready for JSON
    serialisation and UI display.
    """

    # 1. Attack type
    attack_type = _ATTACK_TYPE_MAP.get(alert.event_type, "Unknown")

    # 2. Evidence
    evidence = _extract_evidence(alert)

    # 3. Severity
    score, severity_level = calculate_severity(alert)

    # 4. Severity reasoning
    severity_reasoning = _severity_reasoning(alert, score, severity_level)

    # 5. Risk assessment
    risk = _risk_assessment(severity_level)

    # 6. Recommendations – fallback to generic if attack unknown
    recommendations = _REMEDIATION_CATALOG.get(attack_type, _REMEDIATION_CATALOG["Unknown"])

    return InvestigationResult(
        attack_type=attack_type,
        evidence=evidence,
        severity_reasoning=severity_reasoning,
        risk_assessment=risk,
        recommendations=recommendations,
    )
