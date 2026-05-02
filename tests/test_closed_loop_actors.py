from __future__ import annotations

from pathlib import Path

from badlands.core.datasets import AuthAffinity
from badlands.agents.llm import InvalidLLMDecision, LLMDecision
from badlands.cli import schedule_llm_attacker, schedule_llm_defender
from badlands.core.env import MissionDeskEnv
from badlands.core.state import User
from badlands.core.trace import load_trace


class SequentialAttacker:
    def __init__(self):
        self.actions = ["discover_local", "scan_network", "attempt_credential_access"]
        self.observation_lengths: list[int] = []

    def decide(self, observation):
        self.observation_lengths.append(len(observation.get("results", [])))
        action = self.actions.pop(0)
        return LLMDecision(
            "next",
            action,
            {},
            0.9,
            [],
            "The prior attacker results support continuing the sequence.",
            "The next attacker action will be scheduled.",
            "The action may fail if prerequisites are absent.",
        )


class InvalidThenValidDefender:
    def __init__(self):
        self.n = 0

    def decide(self, observation):
        self.n += 1
        if self.n == 1:
            raise InvalidLLMDecision("defender", {"action": "read_hidden_state"}, "unsupported action")
        return LLMDecision(
            "investigate",
            "query_endpoint",
            {"host_id": "ws-alice"},
            0.5,
            [],
            "The defender needs endpoint evidence before containment.",
            "The query should return endpoint telemetry.",
            "The delay may allow attacker progress.",
        )


class CapturingGreen:
    def __init__(self):
        self.observation = None

    def decide(self, observation):
        self.observation = observation
        return LLMDecision(
            "complete work",
            "use_mission_app",
            {},
            0.8,
            [],
            "The mission app appears available in the user observation.",
            "The user will attempt mission app work.",
            "The app or account may fail during execution.",
        )


class BadEvidenceDefender:
    def decide(self, observation):
        raise InvalidLLMDecision(
            "defender",
            {
                "intent": "bad evidence",
                "action": "query_endpoint",
                "parameters": {"host_id": "ws-alice"},
                "confidence": 0.7,
                "evidence_ids": ["telemetry_001"],
            },
            "evidence_ids not present in observation: telemetry_001",
        )


def test_attacker_llm_closed_loop_observes_prior_results(tmp_path: Path):
    env = MissionDeskEnv(tmp_path / "loop.jsonl", seed=1, no_green=True)
    actor = SequentialAttacker()
    schedule_llm_attacker(env, actor, max_actions=3)
    env.run(30)
    events = load_trace(tmp_path / "loop.jsonl")
    requests = [e for e in events if e["type"] == "action_requested" and e["agent"] == "attacker"]
    decisions = [e for e in events if e["type"] == "llm_decision" and e["agent"] == "attacker"]
    assert len(decisions) == 3
    assert all("rationale" in e["payload"] for e in decisions)
    assert requests[0]["parents"] == [decisions[0]["event_id"]]
    assert [e["timestamp"] for e in requests] == sorted({e["timestamp"] for e in requests})
    assert actor.observation_lengths == [0, 1, 2]


def test_invalid_llm_decision_is_traced_not_coerced(tmp_path: Path):
    env = MissionDeskEnv(tmp_path / "invalid.jsonl", seed=1, no_green=True)
    schedule_llm_defender(env, InvalidThenValidDefender(), max_decisions=2, first_delay=0)
    env.run(20)
    events = load_trace(tmp_path / "invalid.jsonl")
    assert any(e["type"] == "llm_decision_invalid" for e in events)
    assert not any(e["payload"].get("action") == "read_hidden_state" for e in events if e["type"] == "action_requested")
    assert any(e["type"] == "action_requested" and e["payload"].get("action") == "query_endpoint" for e in events)


def test_invalid_live_style_evidence_ids_are_traced_not_crashed(tmp_path: Path):
    env = MissionDeskEnv(tmp_path / "bad-evidence.jsonl", seed=1, no_green=True)
    schedule_llm_defender(env, BadEvidenceDefender(), max_decisions=1, first_delay=0)
    env.run(10)
    events = load_trace(tmp_path / "bad-evidence.jsonl")
    invalid = [e for e in events if e["type"] == "llm_decision_invalid" and e["agent"] == "defender"]
    assert invalid
    assert invalid[0]["payload"]["raw_decision"]["evidence_ids"] == ["telemetry_001"]
    assert not any(e["type"] == "action_requested" and e["agent"] == "defender" for e in events)
    assert any(e["type"] == "score_snapshot" for e in events)


def test_green_llm_observation_does_not_include_account_locked_truth(tmp_path: Path):
    actor = CapturingGreen()
    env = MissionDeskEnv(tmp_path / "green.jsonl", seed=1, no_green=True, user_simulator=actor)
    env.state.users = {"alice": User("alice", "ws-alice", locked=True)}
    env.state.auth_affinities = {"alice": AuthAffinity("alice", "ws-alice", 1, ("idp-1",))}
    env.green_task(0)
    assert actor.observation is not None
    assert "account_locked" not in str(actor.observation)
    assert "app_available" not in str(actor.observation)
    events = load_trace(tmp_path / "green.jsonl")
    assert any(e["type"] == "llm_decision" and e["agent"] == "green" for e in events)
