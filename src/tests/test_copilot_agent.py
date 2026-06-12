"""Tests for src.core.reasoning.copilot_agent.ask_copilot"""

import json
from unittest import mock

import pytest

from src.core.reasoning.copilot_agent import ask_copilot

# Helper objects that mimic the expected interfaces
class DummyModel:
    def __init__(self, data):
        self._data = data
    def json(self):
        return json.dumps(self._data)

# Mock data fixtures
@pytest.fixture
def dummy_alert():
    return DummyModel({"id": "alert-1", "title": "Test alert"})

@pytest.fixture
def dummy_investigation():
    return DummyModel({"steps": []})

@pytest.fixture
def dummy_threat_intel():
    return [DummyModel({"intel": "info"})]

@pytest.fixture
def dummy_ai_report():
    return {"summary": "AI report"}

def test_ask_copilot_success(monkeypatch, dummy_alert, dummy_investigation, dummy_threat_intel, dummy_ai_report):
    # Force environment variables
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.fakeopenai.com/v1")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-test")

    # Mock httpx.Client.post to return a crafted response
    mock_resp = mock.Mock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": "Mocked answer"}}]
    }
    mock_client = mock.Mock()
    mock_client.__enter__.return_value = mock_client
    mock_client.post.return_value = mock_resp
    monkeypatch.setattr("httpx.Client", lambda *args, **kwargs: mock_client)

    answer = ask_copilot(
        question="What is the severity?",
        alert=dummy_alert,
        investigation=dummy_investigation,
        threat_intel=dummy_threat_intel,
        ai_report=dummy_ai_report,
    )
    assert answer == "Mocked answer"
    # Verify payload contains the question and a JSON context
    sent_messages = mock_client.post.call_args[1]["json"]["messages"]
    assert any("Question: What is the severity?" in m["content"] for m in sent_messages)

def test_missing_api_key(monkeypatch, dummy_alert, dummy_investigation, dummy_threat_intel, dummy_ai_report):
    # Ensure API key is not set
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    answer = ask_copilot(
        question="any",
        alert=dummy_alert,
        investigation=dummy_investigation,
        threat_intel=dummy_threat_intel,
        ai_report=dummy_ai_report,
    )
    assert "OPENAI_API_KEY" in answer
