"""Very small rule‑based severity engine.

The engine receives an :class:`Alert` and returns a numeric score
(0‑100) plus the corresponding :class:`SeverityLevel`.  For the MVP we
derive the score from three simple factors:
* ``event_type`` – each known type has a base weight.
* ``source_ip`` – if the IP is in a private range we lower the risk.
* ``dest_ip`` – if the destination is a known critical asset (hard‑coded
  list) we raise the risk.

The logic purposefully stays deterministic – no LLM is needed for this
demonstration.
"""

from __future__ import annotations

from ipaddress import ip_address
from typing import Tuple

from ..models.alert import Alert
from ..models.severity import SeverityLevel

# Simple base scores for a few event types used in the sample alerts.
_EVENT_BASE_SCORES = {
    "ssh_bruteforce": 65,
    "port_scan": 40,
    "malware_detection": 80,
    "suspicious_login": 55,
    "privilege_escalation": 85,
    "data_exfiltration": 90,
    "ransomware": 95,
}

# Hard‑coded critical assets for the demo – in a real product this would
# come from CMDB / asset inventory.
_CRITICAL_ASSETS = {"10.0.0.10", "192.168.1.100"}


def _is_private_ip(ip: str) -> bool:
    try:
        return ip_address(ip).is_private
    except ValueError:
        return False


def calculate_severity(alert: Alert) -> Tuple[int, SeverityLevel]:
    """Return ``(score, level)`` for *alert*.

    Steps:
    1. Look up a base score for ``alert.event_type``; default to 30.
    2. Reduce score by 20 % if ``source_ip`` is private (likely internal).
    3. Increase score by 15 % if ``dest_ip`` is a critical asset.
    4. Clamp the final score to the 0‑100 range and map to a
       :class:`SeverityLevel`.
    """
    base = _EVENT_BASE_SCORES.get(alert.event_type, 30)
    score = base

    if _is_private_ip(alert.source_ip):
        score = int(score * 0.8)
    if alert.dest_ip in _CRITICAL_ASSETS:
        score = int(score * 1.15)

    # Ensure bounds
    score = max(0, min(100, score))
    level = SeverityLevel.from_score(score)
    return score, level
