"""Severity enumeration used by the MVP.

We keep a very small mapping from a numeric score (0‑100) to a
human‑readable level.  The numeric score is calculated by a simple rule‑
based engine in ``severity_engine.py``.
"""

from __future__ import annotations

from enum import Enum


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_score(cls, score: int) -> "SeverityLevel":
        """Map a 0‑100 score to a severity bucket.

        The thresholds are intentionally simple for the hackathon demo:
        * 0‑30   → LOW
        * 31‑60  → MEDIUM
        * 61‑85  → HIGH
        * 86‑100 → CRITICAL
        """
        if score <= 30:
            return cls.LOW
        if score <= 60:
            return cls.MEDIUM
        if score <= 85:
            return cls.HIGH
        return cls.CRITICAL
