from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import pytest

from badlands.agents.llm import AttackerLLM, DefenderLLM, GreenUserLLM, InvalidLLMDecision, OpenAICompatClient
from badlands.core.config import load_env
from badlands.core.observations import assert_no_forbidden


class FakeClient:
    model = "fake"

    def complete_json(self, messages, *, model=None, validator=None):
        assert "contained mission-cyber environment" in messages[0]["content"]
        assert "Cite only event ids you can see" in messages[0]["content"]
        assert "describe uncertainty instead of unsupported conclusions" in messages[0]["content"]
        text = messages[-1]["content"]
        if '"role": "green"' in text:
            assert "You are a mission user" in messages[0]["content"]
            assert "Avoid SOC language" in messages[0]["content"]
            return {
                "intent": "complete mission work",
                "action": "use_mission_app",
                "parameters": {"task": "update"},
                "confidence": 0.8,
                "evidence_ids": [],
                "rationale": "The mission observation shows the app is available.",
                "expected_effect": "The user will attempt normal mission work.",
                "risk": "The app or account may fail after the decision.",
            }
        if '"role": "defender"' in text:
            assert "reduce security risk while preserving mission continuity" in messages[0]["content"]
            assert "mission-continuity risk" in messages[0]["content"]
            return {
                "intent": "investigate",
                "action": "query_endpoint",
                "parameters": {"host_id": "ws-alice"},
                "confidence": 0.7,
                "evidence_ids": [],
                "rationale": "The alert names credential access but more endpoint evidence is needed.",
                "expected_effect": "The defender will receive endpoint telemetry for review.",
                "risk": "Waiting may allow attacker progress during investigation.",
            }
        assert "progress through plausible intrusion stages" in messages[0]["content"]
        assert "Cite visible observation event ids" in messages[0]["content"]
        return {
            "intent": "map enclave",
            "action": "scan_network",
            "parameters": {},
            "confidence": 0.6,
            "evidence_ids": [],
            "rationale": "The visible results mention the mission app service.",
            "expected_effect": "The attacker will enumerate reachable services.",
            "risk": "The scan may generate detectable network telemetry.",
        }


def test_cached_llm_decisions_replay_without_network(tmp_path: Path):
    obs = {"mission": [{"event_id": "evt_1", "status": "app_available"}]}
    actor = GreenUserLLM(cache_dir=tmp_path, seed=1, client=FakeClient())
    first = actor.decide(obs)
    second = GreenUserLLM(cache_dir=tmp_path, seed=1, client=None, model="fake").decide(obs)
    assert first == second
    assert first.action == "use_mission_app"
    assert_no_forbidden(obs)


def test_role_action_boundaries_with_cached_fake(tmp_path: Path):
    assert DefenderLLM(cache_dir=tmp_path, seed=1, client=FakeClient()).decide({"alerts": []}).action in DefenderLLM.actions
    assert AttackerLLM(cache_dir=tmp_path, seed=1, client=FakeClient()).decide({"results": []}).action in AttackerLLM.actions


def test_json_parser_extracts_markdown_wrapped_object():
    parsed = OpenAICompatClient._parse_json('thinking...```json\n{"intent":"x","action":"scan_network","parameters":{},"confidence":0.5,"evidence_ids":[],"rationale":"visible service","expected_effect":"scan services","risk":"creates telemetry"}\n```')
    assert parsed["action"] == "scan_network"


def test_openai_client_sends_vllm_structured_decision_config(monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, object] = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(
                {
                    "choices": [{"message": {"content": '{"action":"scan_network"}'}}],
                    "usage": {"completion_tokens": 5},
                }
            ).encode()

    def fake_urlopen(req, timeout):
        captured["body"] = json.loads(req.data.decode())
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = OpenAICompatClient(base_url="http://llm.local/v1", api_key="EMPTY", model="model")
    schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["action"],
        "properties": {"action": {"type": "string", "enum": ["scan_network"]}},
    }
    client._complete([{"role": "user", "content": "choose"}], model=None, max_tokens=32, json_schema=schema)
    body = captured["body"]
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["strict"] is True
    assert body["response_format"]["json_schema"]["schema"] == schema
    assert body["structured_outputs"]["json"] == schema
    assert body["structured_outputs"]["disable_additional_properties"] is True
    assert body["chat_template_kwargs"] == {"enable_thinking": False}


def test_openai_client_rejects_reasoning_only_response(monkeypatch: pytest.MonkeyPatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(
                {
                    "choices": [{"message": {"content": None, "reasoning": '{"action":"scan_network"}'}}],
                    "usage": {"completion_tokens": 5},
                }
            ).encode()

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: Response())
    client = OpenAICompatClient(base_url="http://llm.local/v1", api_key="EMPTY", model="model")

    with pytest.raises(InvalidLLMDecision, match="returned reasoning content"):
        client.complete_json([{"role": "user", "content": "choose"}])

    assert client.last_completion_telemetry["final_invalid_count"] == 1
    assert "reasoning" in client.last_completion_telemetry["invalid_decision_reason"]


def test_repair_count_counts_attempts_not_failures():
    class MalformedTwiceClient(OpenAICompatClient):
        def __init__(self):
            self.base_url = "fake"
            self.api_key = "fake"
            self.model = "fake"

        def _complete(self, messages, *, model=None, max_tokens=512, json_schema=None):
            return '{"intent": "truncated"'

    client = MalformedTwiceClient()
    with pytest.raises(InvalidLLMDecision) as err:
        client.complete_json([{"role": "user", "content": "bad"}], validator=lambda raw: None)
    assert err.value.telemetry["parse_failures"] == 2
    assert err.value.telemetry["repair_count"] == 1
    assert err.value.telemetry["repairs_attempted"] == 1
    assert err.value.telemetry["repair_invalid_count"] == 1
    assert err.value.telemetry["final_invalid_count"] == 1


def test_invalid_confidence_is_not_cached(tmp_path: Path):
    class BadConfidenceClient:
        model = "fake"
        last_completion_telemetry = {}

        def complete_json(self, messages, *, model=None, validator=None):
            raw = {
                "intent": "complete mission work",
                "action": "use_mission_app",
                "parameters": {},
                "confidence": "high",
                "evidence_ids": [],
                "rationale": "The mission app is visible.",
                "expected_effect": "The user will try mission work.",
                "risk": "The service may be unavailable.",
            }
            if validator is not None:
                validator(raw)
            return raw

    actor = GreenUserLLM(cache_dir=tmp_path, seed=1, client=BadConfidenceClient())
    with pytest.raises(InvalidLLMDecision, match="confidence must be a number"):
        actor.decide({"mission": []})

    assert list(tmp_path.glob("green_*.json")) == []


def test_dotenv_loader_integrates_role_endpoints(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text("BADLANDS_GREEN_LLM_BASE_URL=http://green.local/v1\nBADLANDS_GREEN_LLM_MODEL=green-model\n")
    monkeypatch.delenv("BADLANDS_GREEN_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("BADLANDS_GREEN_LLM_MODEL", raising=False)
    load_env(env_file, override=True)
    actor = GreenUserLLM(cache_dir=tmp_path, seed=1)
    assert actor.client.base_url == "http://green.local/v1"
    assert actor.model == "green-model"


def test_role_specific_env_overrides(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("BADLANDS_DEFENDER_LLM_BASE_URL", "http://defender.local/v1")
    monkeypatch.setenv("BADLANDS_DEFENDER_LLM_API_KEY", "DEF")
    monkeypatch.setenv("BADLANDS_DEFENDER_LLM_MODEL", "badlands-defender-nemotron-nano")
    actor = DefenderLLM(cache_dir=tmp_path, seed=1)
    assert actor.client.base_url == "http://defender.local/v1"
    assert actor.client.api_key == "DEF"
    assert actor.model == "badlands-defender-nemotron-nano"


def test_invalid_llm_action_raises_instead_of_coercing(tmp_path: Path):
    class BadClient:
        model = "fake"

        def complete_json(self, messages, *, model=None, validator=None):
            return {
                "intent": "bad",
                "action": "external_scan",
                "parameters": {},
                "confidence": 1,
                "evidence_ids": [],
                "rationale": "The model wants to scan outside the environment.",
                "expected_effect": "It would leave Badlands.",
                "risk": "The action is outside allowed actions.",
            }

    try:
        AttackerLLM(cache_dir=tmp_path, seed=1, client=BadClient()).decide({"results": []})
    except InvalidLLMDecision as exc:
        assert exc.raw["action"] == "external_scan"
        return
    raise AssertionError("invalid LLM decision was silently accepted")


def test_missing_qualitative_fields_are_invalid(tmp_path: Path):
    class OldShapeClient:
        model = "fake"

        def complete_json(self, messages, *, model=None, validator=None):
            return {"intent": "old", "action": "scan_network", "parameters": {}, "confidence": 1, "evidence_ids": []}

    with pytest.raises(InvalidLLMDecision, match="missing required keys"):
        AttackerLLM(cache_dir=tmp_path, seed=1, client=OldShapeClient()).decide({"results": []})


def test_evidence_ids_must_be_present_in_observation(tmp_path: Path):
    class InventedEvidenceClient:
        model = "fake"

        def complete_json(self, messages, *, model=None, validator=None):
            return {
                "intent": "invent evidence",
                "action": "scan_network",
                "parameters": {},
                "confidence": 1,
                "evidence_ids": ["files-1"],
                "rationale": "The model references a host rather than an event id.",
                "expected_effect": "The scan would run.",
                "risk": "The evidence is not replayable.",
            }

    with pytest.raises(InvalidLLMDecision, match="evidence_ids not present"):
        AttackerLLM(cache_dir=tmp_path, seed=1, client=InventedEvidenceClient()).decide(
            {"results": [{"event_id": "evt_000123", "stdout": "files-1"}]}
        )


def test_validator_retry_exhaustion_preserves_invalid_decision(tmp_path: Path):
    class ExhaustingClient(OpenAICompatClient):
        def __init__(self):
            self.base_url = "fake"
            self.api_key = "fake"
            self.model = "fake"
            self.calls = 0

        def _complete(self, messages, *, model=None, max_tokens=512, json_schema=None):
            self.calls += 1
            return (
                '{"intent":"bad evidence","action":"query_endpoint",'
                '"parameters":{"host_id":"ws-alice"},"confidence":0.7,'
                '"evidence_ids":["telemetry_001","telemetry_002"],'
                '"rationale":"The telemetry labels look relevant.",'
                '"expected_effect":"The defender will query endpoint telemetry.",'
                '"risk":"The cited evidence is not replayable."}'
            )

    client = ExhaustingClient()
    with pytest.raises(InvalidLLMDecision) as err:
        DefenderLLM(cache_dir=tmp_path, seed=1, client=client).decide(
            {"telemetry": [{"event_id": "evt_000123", "ecs": {"host.name": "ws-alice"}}]}
        )
    assert err.value.raw["evidence_ids"] == ["telemetry_001", "telemetry_002"]
    assert "evidence_ids not present" in err.value.reason
    assert client.calls == 1
    assert err.value.telemetry["repair_count"] == 0


def test_llm_transport_failure_becomes_invalid_decision(tmp_path: Path):
    class TimeoutClient:
        model = "fake"

        def complete_json(self, messages, *, model=None, validator=None):
            raise TimeoutError("timed out")

    with pytest.raises(InvalidLLMDecision) as err:
        AttackerLLM(cache_dir=tmp_path, seed=1, client=TimeoutClient()).decide({"results": []})
    assert err.value.raw == {}
    assert "timed out" in err.value.reason
