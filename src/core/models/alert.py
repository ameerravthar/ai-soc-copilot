"""Alert data model used throughout the MVP.

Only a small subset of fields is required for the hackathon demo –
* ``alert_id`` – unique identifier (string)
* ``timestamp`` – ISO‑8601 datetime string
* ``source_ip`` – attacker IP address
* ``dest_ip`` – victim IP address
* ``event_type`` – high‑level type (e.g. ``ssh_bruteforce``)
* ``raw`` – the original JSON payload (kept for display)

The model validates the structure with **pydantic** and provides a
``dict`` representation that the Streamlit UI can render.
"""

from __future__ import annotations

from typing import Any, Dict

from pydantic import BaseModel, Field, validator


class Alert(BaseModel):
    """Simple representation of a security alert.

    The fields are deliberately minimal – they are enough to drive the
    severity engine and MITRE mapping logic while keeping the MVP
    lightweight.
    """

    alert_id: str = Field(..., description="Unique identifier for the alert")
    timestamp: str = Field(..., description="ISO‑8601 timestamp of the event")
    source_ip: str = Field(..., description="IP address of the suspected attacker")
    dest_ip: str = Field(..., description="IP address of the target host")
    event_type: str = Field(..., description="High‑level event type, e.g. ssh_bruteforce")
    raw: Dict[str, Any] = Field(..., description="Original JSON payload for debugging/display")

    @validator("timestamp")
    def _validate_timestamp(cls, v: str) -> str:
        # Very light check – the full parsing is not required for the MVP.
        if "T" not in v:
            raise ValueError("timestamp must be ISO‑8601 format")
        return v

    class Config:
        frozen = True
        json_encoders = {dict: lambda d: d}

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain dict (excluding the original raw payload)."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "event_type": self.event_type,
        }
