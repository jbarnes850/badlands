from __future__ import annotations

import json
import threading
from argparse import Namespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from badlands.agents.llm import AttackerLLM, InvalidLLMDecision, LLMDecision
from badlands.core.env import MissionDeskEnv
from badlands.core.trace import load_trace
from badlands.live_validate import (
    EndpointFailure,
    LiveActorState,
    RoleEndpoint,
    _endpoint_failure_payload,
    _ordered_proposals,
    _write_report,
    build_report,
    configured_endpoints,
    prepare_live_schedule,
    preflight,
    _live_actor_states,
)
from badlands.scoring.replay import derive_scores


class MockVLLMHandler(BaseHTTPRequestHandler):
    model_id = "mock-model"
    invalid_json = False

    def do_GET(self):
        if self.path == "/v1/models":
            self._json(200, {"data": [{"id": self.model_id, "max_model_len": 32768}]})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/v1/chat/completions":
            content = "{not json" if self.invalid_json else '{"ok": true}'
            self._json(
                200,
                {
                    "choices": [{"message": {"content": content}}],
                    "usage": {"prompt_tokens": 11, "completion_tokens": 3},
                },
            )
            return
        self._json(404, {"error": "not found"})

    def log_message(self, format, *args):  # noqa: A002
        return

    def _json(self, status: int, payload: dict):
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@pytest.fixture
def mock_vllm():
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockVLLMHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_preflight_success_for_mock_endpoint(mock_vllm: str):
    endpoints = {
        role: RoleEndpoint(role, mock_vllm, "EMPTY", "mock-model")
        for role in ("green", "attacker", "defender")
    }
    results = preflight(endpoints, chat_timeout=5)
    assert {item["role"] for item in results} == {"green", "attacker", "defender"}
    assert all(item["completion_tokens"] == 3 for item in results)


def test_preflight_missing_model_fails(mock_vllm: str):
    endpoints = {"attacker": RoleEndpoint("attacker", mock_vllm, "EMPTY", "missing-model")}
    with pytest.raises(EndpointFailure, match="configured model id"):
        preflight(endpoints, chat_timeout=5)


def test_configured_endpoints_preserve_shared_infra_role_config(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BADLANDS_DEFENDER_LLM_BASE_URL", "http://shared/v1")
    monkeypatch.setenv("BADLANDS_GREEN_LLM_BASE_URL", "http://shared/v1")
    monkeypatch.setenv("BADLANDS_ATTACKER_LLM_BASE_URL", "http://attacker/v1")
    monkeypatch.setenv("BADLANDS_DEFENDER_LLM_MODEL", "nano")
    monkeypatch.setenv("BADLANDS_GREEN_LLM_MODEL", "nano")
    monkeypatch.setenv("BADLANDS_ATTACKER_LLM_MODEL", "super")
    args = Namespace(
        green_base_url=None,
        green_api_key=None,
        green_model=None,
        attacker_base_url=None,
        attacker_api_key=None,
        attacker_model=None,
        defender_base_url=None,
        defender_api_key=None,
        defender_model=None,
    )
    endpoints = configured_endpoints(args)
    assert endpoints["defender"].base_url == endpoints["green"].base_url
    assert endpoints["defender"].role != endpoints["green"].role
    assert endpoints["attacker"].model == "super"


def test_report_extracts_telemetry_and_role_isolation(tmp_path: Path):
    trace = tmp_path / "trace.jsonl"
    env = MissionDeskEnv(trace, seed=1, no_green=True)
    decision_id = env.trace.emit(
        "llm_decision",
        0,
        {
            "role": "defender",
            "observation": {"alerts": []},
            "observation_event_ids": [],
            "raw_decision": {
                "intent": "investigate",
                "action": "query_endpoint",
                "parameters": {"host_id": "ws-alice"},
                "confidence": 0.7,
                "evidence_ids": [],
                "rationale": "No alert evidence is present, so endpoint review is safest.",
                "expected_effect": "Collect endpoint evidence.",
                "risk": "The attacker may progress while evidence is gathered.",
            },
            "intent": "investigate",
            "action": "query_endpoint",
            "parameters": {"host_id": "ws-alice"},
            "confidence": 0.7,
            "evidence_ids": [],
            "rationale": "No alert evidence is present, so endpoint review is safest.",
            "expected_effect": "Collect endpoint evidence.",
            "risk": "The attacker may progress while evidence is gathered.",
            "inference_telemetry": {
                "role": "defender",
                "endpoint": "http://shared/v1",
                "model": "nano",
                "cache_key": "abc",
                "cache_hit": False,
                "prompt_token_estimate": 100,
                "completion_tokens": 10,
                "wall_latency_s": 2.0,
                "attempt_count": 1,
                "repair_count": 0,
                "validation_error": None,
                "invalid_decision_reason": None,
            },
        },
        agent="defender",
    )
    env.defender("query_endpoint", {"host_id": "ws-alice"}, decision_event_id=decision_id)
    env.run(10)
    args = Namespace(trace=trace, cache=tmp_path / "cache", report=tmp_path / "report.json", seed=1, until=10)
    endpoints = {
        "green": RoleEndpoint("green", "http://shared/v1", "EMPTY", "nano"),
        "defender": RoleEndpoint("defender", "http://shared/v1", "EMPTY", "nano"),
        "attacker": RoleEndpoint("attacker", "http://attacker/v1", "EMPTY", "super"),
    }
    report = build_report(
        args=args,
        endpoints=endpoints,
        preflight_results=[],
        episode={"episode_wall_clock_s": 0.1},
        replay_score=derive_scores(load_trace(trace)),
    )
    assert report["telemetry"]["completion_tokens"] == 10
    assert report["role_isolation"]["shared_endpoint_infrastructure"]["green"] == ["defender"]
    assert report["role_isolation"]["role_scoped_cache_keys"]["ok"] is True
    assert report["deterministic_fan_in"]["observation_snapshot_before_fanout"] is True
    assert "DS-29 owns durable actor memory" in report["ds29_handoff"]["boundary"]


def test_live_schedule_preserves_benign_noise_without_scripted_green(tmp_path: Path):
    env = MissionDeskEnv(tmp_path / "live-schedule.jsonl", seed=7)
    prepare_live_schedule(env)
    env.run(12)
    events = load_trace(tmp_path / "live-schedule.jsonl")
    noise = [
        e for e in events
        if e["type"] == "state_transition" and e["payload"].get("kind") == "benign_noise_scheduled"
    ]
    mission = [e for e in events if e["type"] == "mission_task_event"]
    assert [e["payload"]["noise_kind"] for e in noise] == ["failed_auth_burst", "noisy_script"]
    assert mission == []


def test_live_defender_decision_observation_has_no_benign_only_markers(tmp_path: Path):
    trace = tmp_path / "live-observation.jsonl"
    env = MissionDeskEnv(trace, seed=7)
    prepare_live_schedule(env)
    env.run(12)
    observation = env.defender_observation()
    decision_id = env.trace.emit(
        "llm_decision",
        env.now,
        {
            "role": "defender",
            "observation": observation,
            "observation_event_ids": [item["event_id"] for item in observation["alerts"] + observation["telemetry"]],
            "raw_decision": {
                "intent": "triage",
                "action": "triage_alert",
                "parameters": {},
                "confidence": 0.5,
                "evidence_ids": [],
                "rationale": "Investigate ambiguous evidence before containment.",
                "expected_effect": "Review alert context.",
                "risk": "Delay may allow attacker progress.",
            },
            "intent": "triage",
            "action": "triage_alert",
            "parameters": {},
            "confidence": 0.5,
            "evidence_ids": [],
            "rationale": "Investigate ambiguous evidence before containment.",
            "expected_effect": "Review alert context.",
            "risk": "Delay may allow attacker progress.",
            "inference_telemetry": {},
        },
        agent="defender",
    )
    env.run(13)
    events = load_trace(trace)
    decision = [e for e in events if e["event_id"] == decision_id][0]
    text = str(decision["payload"]["observation"])
    assert not any(
        marker in text
        for marker in [
            "false_positive",
            "known_false_positive",
            "benign_noise",
            "benign_noise_scheduled",
            "noise-000",
            "badlands.alert.notes",
        ]
    )


def test_malformed_outputs_are_preserved_on_invalid_decision(tmp_path: Path):
    class MalformedClient:
        model = "fake"

        def complete_json(self, messages, *, model=None, validator=None):
            raise InvalidLLMDecision(
                "attacker",
                {"raw_outputs": [{"attempt": 1, "max_tokens": 384, "content": '{"intent": "bad" extra'}]},
                "LLM did not return parseable JSON after retries: Extra data",
                {
                    "endpoint": "test-client",
                    "model": "fake",
                    "cache_hit": False,
                    "cache_key": "abc",
                    "completion_tokens": 12,
                    "wall_latency_s": 0.1,
                    "attempt_count": 1,
                    "repair_count": 0,
                    "validation_error": "Extra data",
                    "invalid_decision_reason": "Extra data",
                    "raw_outputs": [{"attempt": 1, "max_tokens": 384, "content": '{"intent": "bad" extra'}],
                },
            )

    with pytest.raises(InvalidLLMDecision) as err:
        AttackerLLM(cache_dir=tmp_path, seed=1, client=MalformedClient()).decide({"results": []})
    assert err.value.raw["raw_outputs"][0]["content"] == '{"intent": "bad" extra'
    assert err.value.telemetry["raw_outputs"][0]["max_tokens"] == 384


def test_report_includes_invalid_decisions_for_qualitative_review(tmp_path: Path):
    trace = tmp_path / "invalid.jsonl"
    env = MissionDeskEnv(trace, seed=1, no_green=True)
    env.trace.emit(
        "llm_decision_invalid",
        0,
        {
            "role": "green",
            "raw_decision": {"raw_outputs": [{"attempt": 1, "content": "{bad json"}]},
            "reason": "parse failure",
            "observation": {"mission": []},
            "inference_telemetry": {
                "role": "green",
                "endpoint": "http://shared/v1",
                "model": "nano",
                "cache_key": "green_bad",
                "cache_path": str(tmp_path / "green_bad.json"),
                "cache_hit": False,
                "completion_tokens": 5,
                "wall_latency_s": 1.0,
                "attempt_count": 1,
                "repair_count": 0,
                "raw_outputs": [{"attempt": 1, "content": "{bad json"}],
            },
        },
        agent="green",
    )
    env.run(1)
    args = Namespace(trace=trace, cache=tmp_path, report=tmp_path / "report.json", seed=1, until=1)
    endpoints = {
        "green": RoleEndpoint("green", "http://shared/v1", "EMPTY", "nano"),
        "defender": RoleEndpoint("defender", "http://shared/v1", "EMPTY", "nano"),
        "attacker": RoleEndpoint("attacker", "http://attacker/v1", "EMPTY", "super"),
    }
    report = build_report(
        args=args,
        endpoints=endpoints,
        preflight_results=[],
        episode={"episode_wall_clock_s": 0.1},
        replay_score=derive_scores(load_trace(trace)),
    )
    invalid = report["qualitative_output_checklist"]["green"][0]
    assert invalid["event_type"] == "llm_decision_invalid"
    assert invalid["raw_outputs"][0]["content"] == "{bad json"


def test_backpressure_unavailable_is_explicit_in_preflight(mock_vllm: str):
    endpoints = {"attacker": RoleEndpoint("attacker", mock_vllm, "EMPTY", "mock-model")}
    result = preflight(endpoints, chat_timeout=5)[0]
    assert result["ttft_status"] == "unavailable_non_streaming_preflight"
    assert result["backpressure"]["status"] == "unavailable"
    assert result["backpressure"]["metrics_url"].endswith("/metrics")


def test_score_snapshot_missing_is_exact_blocker(tmp_path: Path):
    trace = tmp_path / "empty.jsonl"
    MissionDeskEnv(trace, seed=1, no_green=True)
    args = Namespace(trace=trace, cache=tmp_path, report=tmp_path / "report.json", seed=1, until=1)
    endpoints = {
        "green": RoleEndpoint("green", "http://shared/v1", "EMPTY", "nano"),
        "defender": RoleEndpoint("defender", "http://shared/v1", "EMPTY", "nano"),
        "attacker": RoleEndpoint("attacker", "http://attacker/v1", "EMPTY", "super"),
    }
    with pytest.raises(RuntimeError, match="completed-run blocker: score_snapshot missing"):
        build_report(args=args, endpoints=endpoints, preflight_results=[], episode={"episode_wall_clock_s": 0.1}, replay_score={})


def test_endpoint_failure_report_payload_is_written(tmp_path: Path):
    report = tmp_path / "failed.json"
    exc = EndpointFailure("attacker", "http://down/v1", "/v1/models", "connection refused")
    payload = _endpoint_failure_payload(exc)
    _write_report(report, payload)
    written = json.loads(report.read_text())
    assert written["failure_classification"]["endpoint_failure"] is True
    assert written["endpoint"] == "http://down/v1"


def test_fan_in_order_is_deterministic_by_role():
    states = [
        LiveActorState("defender", object(), 0, 1, 0, 0, {}, lambda: {}, lambda decision, event_id: None),
        LiveActorState("green", object(), 0, 1, 0, 0, {}, lambda: {}, lambda decision, event_id: None),
        LiveActorState("attacker", object(), 0, 1, 0, 0, {}, lambda: {}, lambda decision, event_id: None),
    ]
    ordered = _ordered_proposals([(state, {}) for state in states], [Exception("d"), Exception("g"), Exception("a")])
    assert [item[0][0].role for item in ordered] == ["green", "attacker", "defender"]


def test_live_green_apply_submits_selected_action(tmp_path: Path):
    trace = tmp_path / "green-action.jsonl"
    env = MissionDeskEnv(trace, seed=1)
    env.queue.clear()
    decision_event = env.trace.emit(
        "llm_decision",
        0,
        {
            "role": "green",
            "observation": {"mission": []},
            "observation_event_ids": [],
            "raw_decision": {
                "intent": "report blockage",
                "action": "create_ticket",
                "parameters": {"reason": "blocked"},
                "confidence": 0.8,
                "evidence_ids": [],
                "rationale": "The user needs help with the task.",
                "expected_effect": "Create a user-visible support ticket.",
                "risk": "The mission task may remain blocked.",
            },
            "intent": "report blockage",
            "action": "create_ticket",
            "parameters": {"reason": "blocked"},
            "confidence": 0.8,
            "evidence_ids": [],
            "rationale": "The user needs help with the task.",
            "expected_effect": "Create a user-visible support ticket.",
            "risk": "The mission task may remain blocked.",
        },
        agent="green",
    )
    env.green_task(
        0,
        selected_action="create_ticket",
        selected_parameters={"reason": "blocked"},
        decision_event_id=decision_event,
    )
    events = load_trace(trace)
    requests = [event for event in events if event["type"] == "action_requested" and event["agent"] == "green"]
    completions = [event for event in events if event["type"] == "action_completed" and event["agent"] == "green"]
    mission = [event for event in events if event["type"] == "mission_task_event"]
    assert requests[-1]["payload"]["action"] == "create_ticket"
    assert requests[-1]["parents"] == [decision_event]
    assert completions[-1]["payload"]["action"] == "create_ticket"
    assert mission[-1]["payload"]["status"] == "failed"
    assert mission[-1]["payload"]["ticket"] is True


def test_live_green_observation_uses_scenario_workflow(tmp_path: Path):
    trace = tmp_path / "green-workflow.jsonl"
    env = MissionDeskEnv(trace, seed=1)
    env.queue.clear()
    args = Namespace(
        cache=tmp_path / "cache",
        seed=1,
        green_decisions=1,
        attacker_decisions=0,
        defender_decisions=0,
        defender_first_delay=0,
    )
    states = _live_actor_states(env, args)
    observation = states["green"].observe()
    assert observation["workflow"]["task_id"] == "wf-001"
    assert observation["workflow"]["workflow_id"] == "mission-package-cycle"
    assert observation["workflow"]["task_type"] == "use_mission_app"
    assert observation["user"]["role"] == "mission_analyst"
    assert observation["mission"][0]["deadline_at"] == 8

    decision = LLMDecision(
        "report blockage",
        "create_ticket",
        {"reason": "blocked"},
        0.8,
        [],
        "The user needs help with the assigned workflow.",
        "Create a visible support ticket.",
        "The mission task may remain blocked.",
    )
    decision_event = env.trace.emit("llm_decision", 0, decision.trace_payload("green", observation), agent="green")
    states["green"].apply(decision, decision_event)
    events = load_trace(trace)
    requests = [event for event in events if event["type"] == "action_requested" and event["agent"] == "green"]
    mission = [event for event in events if event["type"] == "mission_task_event"]
    assert requests[-1]["parents"] == [decision_event]
    assert mission[-1]["payload"]["task_id"] == "wf-001"
