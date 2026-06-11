"""Pydantic model representing the output of the deterministic investigation agent.

The schema mirrors the JSON structure required by the hackathon spec and is
intended to be easily serialisable for UI display or downstream consumption.
"""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field


class InvestigationResult(BaseModel):
    """Structured output of the rule‑based investigation.

    * ``attack_type`` – high‑level classification (derived from ``event_type``).
    * ``evidence`` – list of strings describing which alert fields were used.
    * ``severity_reasoning`` – human readable justification for the severity.
    * ``risk_assessment`` – short risk statement (e.g. "High risk …").
    * ``recommendations`` – actionable remediation steps.
    """

    attack_type: str = Field(..., description="Derived attack classification")
    evidence: List[str] = Field(..., description="Key alert fields that support the classification")
    severity_reasoning: str = Field(..., description="Why the chosen severity level was assigned")
    risk_assessment: str = Field(..., description="Overall risk statement for the alert")
    recommendations: List[str] = Field(..., description="Suggested remediation actions")
