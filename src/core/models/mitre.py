"""MITRE ATT&CK data models for the MVP.

Only the fields required for display are captured:
* ``technique_id`` – e.g. ``T1110``
* ``technique_name`` – human readable name
* ``tactic`` – high‑level MITRE tactic (e.g. ``Credential Access``)
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class MitreTechnique(BaseModel):
    technique_id: str = Field(..., description="MITRE technique identifier, e.g. T1110")
    technique_name: str = Field(..., description="Full technique name")
    tactic: str = Field(..., description="Associated MITRE tactic")
