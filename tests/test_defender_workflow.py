from __future__ import annotations

from badlands.agents.llm import DefenderLLM
from badlands.core.defender_actions import DEFENDER_ACTIONS, DEFENDER_ACTION_DURATIONS
from badlands.core.env import MissionDeskEnv
from badlands.core.observations import assert_no_forbidden, defender_view
from badlands.core.trace import load_trace
from badlands.scoring.replay import derive_scores


def _completed(events: list[dict], action: str) -> list[dict]:
    return [
        event for event in events
        if event["type"] == "action_completed"
        and event.get("agent") == "defender"
        and event["payload"].get("action") == action
    ]


def test_defender_action_surface_is_centralized() -> None:
    assert DefenderLLM.actions == DEFENDER_ACTIONS
    assert set(DEFENDER_ACTION_DURATIONS) == set(DEFENDER_ACTIONS)
    assert {"query_network", "block_indicator", "kill_process", "restore_host_or_service", "escalate"} <= set(DEFENDER_ACTIONS)


def test_query_triage_escalate_results_are_observable_without_hidden_truth(tmp_path):
    env = MissionDeskEnv(tmp_path / "case.jsonl", seed=7, perfect_sensors=True)
    env.attacker("scan_network")
    env.run(12)
    env.defender("triage_alert", {"alert_id": "latest"})
    env.defender("query_network", {"host_id": "ws-alice"})
    env.defender("escalate", {"case_id": "case-latest"})
    env.run(25)

    events = load_trace(tmp_path / "case.jsonl")
    obs = defender_view(events)
    assert_no_forbidden(obs)
    assert _completed(events, "triage_alert")[-1]["payload"]["source_event_ids"]
    assert _completed(events, "query_network")[-1]["payload"]["network_events"]
    assert _completed(events, "escalate")[-1]["payload"]["case_note"]
    assert any(case["action"] == "escalate" for case in obs["cases"])
    assert "audit_true_positive" not in str(obs)


def test_block_indicator_has_service_side_effect_and_replay_evidence(tmp_path):
    env = MissionDeskEnv(tmp_path / "block.jsonl", seed=1)
    env.defender("block_indicator", {"type": "host", "value": "app-1", "scope": "enclave"})
    env.schedule(5, lambda: env.green_task(0))
    score = env.run(15)

    events = load_trace(tmp_path / "block.jsonl")
    completed = _completed(events, "block_indicator")[-1]
    assert completed["payload"]["source_event_ids"]
    assert any(
        event["type"] == "dependency_state_changed"
        and event["payload"].get("reason") == "defender_indicator_block"
        for event in events
    )
    assert score == derive_scores(events)
    assert score["service_downtime_minutes"] > 0
    assert score["mission_tasks_failed"] > 0


def test_block_indicator_rejects_unmodeled_indicator_without_side_effect(tmp_path):
    env = MissionDeskEnv(tmp_path / "block-reject.jsonl", seed=1, no_green=True)
    env.defender("block_indicator", {"type": "domain", "value": "unknown.example", "scope": "enclave"})
    env.run(5)
    events = load_trace(tmp_path / "block-reject.jsonl")
    completed = _completed(events, "block_indicator")[-1]
    assert completed["payload"]["success"] is False
    assert completed["payload"]["outcome"] == "unsupported_or_unmatched_indicator"
    assert not any(
        event["type"] == "dependency_state_changed"
        and event["payload"].get("reason") == "defender_indicator_block"
        for event in events
    )


def test_kill_process_success_failure_and_harm_are_trace_backed(tmp_path):
    env = MissionDeskEnv(tmp_path / "kill.jsonl", seed=7)
    env.run(14)
    env.defender("kill_process", {"host_id": "ws-dave", "process_ref": "mission-cache-refresh"})
    env.defender("kill_process", {"host_id": "ws-dave", "process_ref": "missing-process"})
    env.run(25)

    events = load_trace(tmp_path / "kill.jsonl")
    kills = _completed(events, "kill_process")
    assert kills[0]["payload"]["success"] is True
    assert kills[1]["payload"]["success"] is False
    assert any(event["type"] == "defense_harm_event" and event["payload"].get("field") == "benign_process_kills" for event in events)
    assert derive_scores(events)["benign_process_kills"] > 0
    assert_no_forbidden(defender_view(events))


def test_kill_process_persistence_eviction_bounds_replay_persistence_minutes(tmp_path):
    env = MissionDeskEnv(tmp_path / "kill-persistence.jsonl", seed=1, no_green=True)
    env.attacker("establish_persistence")
    env.schedule(6, lambda: env.defender("kill_process", {"host_id": "ws-alice", "process_ref": "/tmp/.mission-updater"}))
    env.run(20)

    events = load_trace(tmp_path / "kill-persistence.jsonl")
    assert _completed(events, "kill_process")[-1]["payload"]["success"] is True
    assert any(
        event["type"] == "security_impact_event"
        and event["payload"].get("kind") == "persistence_removed"
        for event in events
    )
    score = derive_scores(events)
    assert score["true_positive_actions"] == 1
    assert 0 < score["persistence_minutes"] < 20


def test_restore_and_rollback_reverse_disruptive_actions(tmp_path):
    env = MissionDeskEnv(tmp_path / "restore.jsonl", seed=1)
    env.defender("isolate_host", {"host_id": "app-1"})
    env.schedule(4, lambda: env.defender("restore_host_or_service", {"target": "app-1"}))
    env.schedule(12, lambda: env.green_task(0))
    env.run(25)
    assert env.state.hosts["app-1"].isolated is False
    assert env.dependency_states["host:app-1"] == "available"
    assert derive_scores(load_trace(tmp_path / "restore.jsonl"))["mission_tasks_completed"] > 0

    rollback = MissionDeskEnv(tmp_path / "rollback.jsonl", seed=1)
    rollback.defender("reset_account", {"user_id": "alice"})
    rollback.schedule(4, lambda: rollback.defender("rollback", {"target": "alice"}))
    rollback.schedule(10, lambda: rollback.green_task(0))
    rollback.run(25)
    events = load_trace(tmp_path / "rollback.jsonl")
    assert rollback.state.users["alice"].locked is False
    assert _completed(events, "rollback")[-1]["payload"]["source_event_ids"]
    assert derive_scores(events)["mission_tasks_completed"] > 0


def test_evidence_gathering_mission_dominates_premature_containment(tmp_path):
    from argparse import Namespace

    from badlands.cli import run_episode

    def args(trace, defender):
        return Namespace(
            trace=trace,
            seed=7,
            until=60,
            defender=defender,
            no_persistence=False,
            no_green=False,
            no_noise=False,
            perfect_sensors=False,
            magic_observations=False,
            service_url=None,
            llm_cache=tmp_path / "llm",
            green_actor="scripted",
            attacker_actor="scripted",
            defender_actor="baseline",
        )

    evidence = run_episode(args(tmp_path / "evidence.jsonl", "evidence_gathering"))
    premature = run_episode(args(tmp_path / "premature.jsonl", "isolate_everything"))
    assert evidence["overall_mission_score"] > premature["overall_mission_score"]
    assert evidence["host_isolation_minutes"] < premature["host_isolation_minutes"]
