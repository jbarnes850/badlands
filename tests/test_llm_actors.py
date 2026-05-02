from __future__ import annotations

from pathlib import Path

import pytest

from badlands.agents.llm import AttackerLLM, DefenderLLM, GreenUserLLM, InvalidLLMDecision, OpenAICompatClient
from badlands.core.config import load_env
from badlands.core.observations import assert_no_forbidden


class FakeClient:
    model = "fake"

    def complete_json(self, messages, *, model=None, validator=None):
        assert "contained mission-cyber environment" in messages[0]["content"]
        text = messages[-1]["content"]
        if '"role": "green"' in text:
            assert "You are a mission user" in messages[0]["content"]
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

        def _complete(self, messages, *, model=None, max_tokens=512):
            return (
                '{"intent":"bad evidence","action":"query_endpoint",'
                '"parameters":{"host_id":"ws-alice"},"confidence":0.7,'
                '"evidence_ids":["telemetry_001","telemetry_002"],'
                '"rationale":"The telemetry labels look relevant.",'
                '"expected_effect":"The defender will query endpoint telemetry.",'
                '"risk":"The cited evidence is not replayable."}'
            )

    with pytest.raises(InvalidLLMDecision) as err:
        DefenderLLM(cache_dir=tmp_path, seed=1, client=ExhaustingClient()).decide(
            {"telemetry": [{"event_id": "evt_000123", "ecs": {"host.name": "ws-alice"}}]}
        )
    assert err.value.raw["evidence_ids"] == ["telemetry_001", "telemetry_002"]
    assert "evidence_ids not present" in err.value.reason
