# AI SOC Copilot

AI-powered SOC Incident Triage and Investigation Assistant built with Python, Streamlit, MITRE ATT&CK mapping, deterministic investigation logic, and LLM-powered analyst reporting.

---

## Overview

AI SOC Copilot is a Security Operations Center (SOC) assistant designed to help analysts triage, investigate, and understand security alerts.

The platform combines deterministic security analysis with AI-generated analyst reports to provide both accurate technical findings and human-readable incident summaries.

The project demonstrates how AI can augment SOC workflows by reducing investigation time and improving analyst productivity.

---

## Features

### Alert Ingestion

* Upload JSON security alerts
* Load predefined sample alerts
* Validate alert structure

### Severity Analysis

* Deterministic severity scoring
* Risk classification
* Context-aware severity adjustments

### MITRE ATT&CK Mapping

* Automatic technique identification
* ATT&CK tactic mapping
* Technique descriptions

### Investigation Agent

* Attack classification
* Evidence extraction
* Severity reasoning
* Risk assessment
* Remediation recommendations

### AI Security Analyst

* Executive summaries
* Technical findings
* Risk analysis
* Recommended actions
* Human-readable SOC reports

### Interactive Dashboard

* Streamlit-based UI
* Incident overview
* Investigation timeline
* Analyst notes
* AI-generated reports

---

## Supported Attack Types

| Attack Type          | MITRE Technique |
| -------------------- | --------------- |
| SSH Brute Force      | T1110           |
| Port Scan            | T1595           |
| Malware Detection    | T1204           |
| Privilege Escalation | T1068           |
| Suspicious Login     | T1078           |
| Data Exfiltration    | T1048           |

---

## Architecture

```text
Security Alert
      │
      ▼
Alert Parser
      │
      ▼
Severity Engine
      │
      ▼
MITRE Mapper
      │
      ▼
Investigation Agent
      │
      ▼
Structured Findings
      │
      ▼
AI Security Analyst
      │
      ▼
SOC Investigation Report
```

---

## Project Structure

```text
ai-soc-copilot/
│
├── data/
│   ├── mitre_map.json
│   └── sample_alerts/
│
├── src/
│   ├── adapters/
│   │   └── streamlit_ui.py
│   │
│   ├── core/
│   │   ├── models/
│   │   └── reasoning/
│   │
│   └── __init__.py
│
├── requirements.txt
└── README.md
```

---

## Installation

### Clone Repository

```bash
git clone https://github.com/ameerravthar/ai-soc-copilot.git
cd ai-soc-copilot
```

### Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## OpenRouter / OpenAI Configuration

```bash
export OPENAI_API_KEY="YOUR_API_KEY"
export OPENAI_BASE_URL="https://openrouter.ai/api/v1"
export OPENAI_MODEL="openai/gpt-oss-120b:free"
```

---

## Run Application

```bash
PYTHONPATH=. streamlit run src/adapters/streamlit_ui.py
```

Open:

```text
http://localhost:8501
```

---

## Sample Workflow

1. Select a sample alert.
2. Review severity assessment.
3. Review MITRE ATT&CK mapping.
4. Review investigation findings.
5. Generate AI analyst report.
6. Review recommendations.

---

## Screenshots

### Incident Overview

Add screenshot here.

### Investigation Findings

Add screenshot here.

### AI Analyst Report

Add screenshot here.

---

## Roadmap

## Prerequisites
- Python 3.10 or newer
- Internet access for OpenAI/OpenRouter API calls
- Basic familiarity with Streamlit (optional)

## Installation
*(Already described above)*

## Environment Configuration
Create a `.env` file (or copy `.env.example`) with the following variables:
```
OPENAI_API_KEY=your_api_key_here
OPENAI_BASE_URL=https://openrouter.ai/api/v1
OPENAI_MODEL=openai/gpt-4o-mini
```
These will be loaded automatically at runtime.

## Running the Demo
```bash
PYTHONPATH=. streamlit run src/adapters/streamlit_ui.py
```
Open `http://localhost:8501` in your browser.

## Feature Checklist
- [x] Alert ingestion (JSON upload / sample picker)
- [x] Deterministic severity scoring
- [x] MITRE ATT&CK mapping
- [x] Investigation agent with evidence and recommendations
- [x] AI analyst report generation (optional, requires API key)
- [x] Threat Intelligence enrichment
- [x] Interactive Copilot Q&A

## Troubleshooting
- **Missing OpenAI key** – The UI will show a warning; set the env var and restart.
- **Dependency errors** – Ensure you are in the virtual environment and run `pip install -r requirements.txt`.
- **Port conflicts** – Change the Streamlit port with `streamlit run ... --server.port 8502`.

## Roadmap

### Phase 1

* Alert ingestion
* Severity scoring
* MITRE mapping

### Phase 2

* Investigation agent
* Evidence analysis
* Risk assessment

### Phase 3

* AI analyst reporting
* OpenRouter integration

### Planned Enhancements

* Threat Intelligence Enrichment
* IOC Reputation Lookup
* Alert Correlation Engine
* Multi-Incident Investigation
* Chat with Incident
* Threat Hunting Assistant
* Azure AI Foundry Integration
* Multi-Agent Architecture

---

## Technologies Used

* Python
* Streamlit
* Pydantic
* MITRE ATT&CK
* OpenRouter
* OpenAI-Compatible APIs
* Git
* GitHub

---

## Use Cases

* SOC Analyst Training
* Security Automation Research
* Incident Response Demonstrations
* Cybersecurity Portfolio Projects
* AI Security Agent Experiments

---

## Author

**Ameer Hamzaa**

AI SOC Copilot is an educational and research project demonstrating AI-assisted security operations workflows.
