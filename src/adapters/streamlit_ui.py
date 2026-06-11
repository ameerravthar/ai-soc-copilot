"""SOC‑style Streamlit UI for the AI SOC Copilot MVP.

Features added in Phase 2.5:
* Analyst‑style evidence and severity reasoning.
* Rich risk assessment text.
* Incident Overview panel.
* Enhanced timeline with more steps.
* Severity badge with color coding.
* Expanded sections (Analyst Notes, Investigation Findings).
* UI uses expanders, metric cards and spacing for a dashboard feel.
"""

from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

# --- Core imports ----------------------------------------------------------
from src.core.models.alert import Alert
from src.core.models.severity import SeverityLevel
from src.core.models.investigation import InvestigationResult
from src.core.reasoning.severity_engine import calculate_severity
from src.core.reasoning.mitre_mapper import map_to_mitre
from src.core.reasoning.investigation_agent import investigate

# --- Helper utilities ------------------------------------------------------

def load_json(file_path: Path) -> dict:
    """Load a JSON file; errors surface in the UI."""
    with file_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)

def parse_alert(raw: dict) -> Alert:
    """Validate and wrap raw dict into an :class:`Alert` model."""
    return Alert(**raw, raw=raw)

def severity_badge(level: SeverityLevel) -> str:
    """Return an HTML badge with color matching the severity level."""
    colors = {
        SeverityLevel.LOW: "#28a745",
        SeverityLevel.MEDIUM: "#ffc107",
        SeverityLevel.HIGH: "#fd7e14",
        SeverityLevel.CRITICAL: "#dc3545",
    }
    return f"<span style='background:{colors[level]};color:white;padding:2px 6px;border-radius:4px'>{level.value}</span>"

# --- Streamlit layout ------------------------------------------------------

def main() -> None:
    st.set_page_config(page_title="AI SOC Copilot MVP", layout="wide")
    st.title("🛡️ AI SOC Copilot – Incident Triage")

    # -------- Sidebar – sample picker ---------------------------------------
    st.sidebar.header("Sample alerts")
    sample_dir = Path(__file__).resolve().parents[2] / "data" / "sample_alerts"
    sample_files = sorted(sample_dir.glob("*.json"))
    sample_map = {f.name: f for f in sample_files}
    selected = st.sidebar.selectbox("Choose a sample", ["-- none --"] + list(sample_map))

    # -------- Main upload area --------------------------------------------
    uploaded = st.file_uploader("Upload JSON alert", type="json")

    if uploaded is not None:
        raw_alert = json.load(uploaded)
    elif selected != "-- none --":
        raw_alert = load_json(sample_map[selected])
    else:
        st.info("Upload an alert JSON or pick a sample to start the investigation.")
        return

    # -------- Raw JSON (expander) ----------------------------------------
    with st.expander("Raw alert JSON", expanded=False):
        st.json(raw_alert)

    # -------- Parse and validate ------------------------------------------
    try:
        alert = parse_alert(raw_alert)
    except Exception as exc:  # pylint: disable=broad-except
        st.error(f"❌ Invalid alert format: {exc}")
        return

    # -------- Run pipelines ------------------------------------------------
    investigation: InvestigationResult = investigate(alert)
    techniques = map_to_mitre(alert)
    score, sev_level = calculate_severity(alert)

    # -------- Incident Overview --------------------------------------------
    st.subheader("Incident Overview")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Attack Type", investigation.attack_type)
    col2.metric("Severity", "", "")
    col2.markdown(severity_badge(sev_level), unsafe_allow_html=True)
    col3.metric("Risk Level", sev_level.value)
    col4.metric("MITRE Technique", ", ".join(t.technique_id for t in techniques))

    # -------- Investigation Timeline ---------------------------------------
    st.subheader("Investigation Timeline")
    timeline_steps = [
        "Alert Received",
        "Alert Parsed",
        "Evidence Collected",
        "Attack Classified",
        "MITRE Technique Identified",
        "Severity Calculated",
        "Risk Assessed",
        "Recommendations Generated",
        "Investigation Completed",
    ]
    for step in timeline_steps:
        st.write(f"✅ {step}")

    # -------- Detailed Findings --------------------------------------------
    st.subheader("Investigation Findings")
    st.markdown("**Attack Type:** " + investigation.attack_type)
    st.markdown("**Evidence:**")
    for ev in investigation.evidence:
        st.write(f"- {ev}")

    st.markdown("**Severity Reasoning:**")
    st.write(investigation.severity_reasoning)

    st.markdown("**Risk Assessment:**")
    st.write(investigation.risk_assessment)

    st.subheader("MITRE ATT&CK Mapping")
    for tech in techniques:
        st.markdown(
            f"* **{tech.technique_id} – {tech.technique_name}**  \
            _Tactic_: {tech.tactic}")

    st.subheader("Recommended Actions")
    for rec in investigation.recommendations:
        st.write(f"- {rec}")

    # -------- Analyst Notes ------------------------------------------------
    st.subheader("Analyst Notes")
    notes = (
        f"The observed activity matches a **{investigation.attack_type}**. "
        f"{investigation.severity_reasoning} "
        f"{investigation.risk_assessment}"
    )
    st.info(notes)

    # -------- Summary -------------------------------------------------------
    st.subheader("Summary")
    st.write(
        f"Alert `{alert.event_type}` from `{alert.source_ip}` targeting `{alert.dest_ip}` "
        f"was evaluated as **{sev_level.value}** (score {score}) with risk: {investigation.risk_assessment}"
    )

if __name__ == "__main__":
    main()
