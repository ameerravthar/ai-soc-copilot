"""Static MITRE ATT&CK mapper for the MVP.

A tiny subset of techniques is stored in ``data/mitre_map.json``.  The
mapper receives an :class:`Alert` and returns a list of
:class:`MitreTechnique` objects that best describe the activity.

The mapping is rule‑based – no external LLM call – which keeps the demo
self‑contained and fast.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from ..models.alert import Alert
from ..models.mitre import MitreTechnique

# Load the static mapping once at import time.
_MAP_FILE = Path(__file__).resolve().parents[3] / "data" / "mitre_map.json"
if not _MAP_FILE.is_file():
    raise FileNotFoundError(f"MITRE map file not found: {_MAP_FILE}")

with _MAP_FILE.open("r", encoding="utf-8") as fh:
    _RAW_MAP = json.load(fh)

# ``_RAW_MAP`` structure:
# {
#   "event_type": [{"technique_id": "T1110", "technique_name": "...", "tactic": "..."}, ...]
# }


def map_to_mitre(alert: Alert) -> List[MitreTechnique]:
    """Return a list of MITRE techniques for *alert*.

    If the ``event_type`` is unknown we fall back to a generic
    ``"T1082"`` (System Information Discovery) entry.
    """
    entries = _RAW_MAP.get(alert.event_type, [])
    if not entries:
        entries = [_RAW_MAP.get("default", [{
            "technique_id": "T1082",
            "technique_name": "System Information Discovery",
            "tactic": "Discovery"
        }])[0]]
    return [MitreTechnique(**e) for e in entries]
