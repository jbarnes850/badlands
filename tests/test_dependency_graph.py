from __future__ import annotations

from pathlib import Path

from argparse import Namespace

from badlands.cli import run_episode
from badlands.core.datasets import AuthAffinity
from badlands.core.dependencies import AVAILABLE, DEGRADED, UNAVAILABLE
from badlands.core.env import MissionDeskEnv
from badlands.core.observations import attacker_view, defender_view, green_view
from badlands.core.state import User
from badlands.core.trace import load_trace


def _single_alice(env: MissionDeskEnv) -> None:
    env.state.users = {"alice": User("alice", "ws-alice")}
    env.state.auth_affinities = {"alice": AuthAffinity("alice", "ws-alice", 1, ("idp-1",))}


def test_upstream_degradation_changes_downstream_mission_outcome(tmp_path: Path):
    healthy = MissionDeskEnv(tmp_path / "healthy.jsonl", seed=1, no_green=True)
    _single_alice(healthy)
    healthy.green_task(0)
    healthy_score = healthy.run(5)

    degraded = MissionDeskEnv(tmp_path / "degraded.jsonl", seed=1, no_green=True)
    _single_alice(degraded)
    degraded._set_dependency_state("service:file_share", DEGRADED, "test_file_share_degraded")
    degraded.green_task(0)
    degraded_score = degraded.run(5)

    assert healthy_score["mission_tasks_completed"] == 1
    assert degraded_score["mission_tasks_failed"] == 1
    assert degraded_score["overall_mission_score"] < healthy_score["overall_mission_score"]
    events = load_trace(tmp_path / "degraded.jsonl")
    failed = [e for e in events if e["type"] == "mission_task_event" and e["payload"].get("status") == "failed"][-1]
    evidence = [e for e in events if e["event_id"] in set(failed["payload"]["source_event_ids"])]
    assert any(e["type"] == "dependency_state_changed" and e["payload"]["ref"] == "file_share" for e in events)
    assert any(e["payload"].get("category") == "service" and e["payload"]["ecs"].get("event.reason") == "dependency_degraded" for e in evidence)


def test_recovery_changes_later_mission_outcome(tmp_path: Path):
    env = MissionDeskEnv(tmp_path / "recovery.jsonl", seed=1, no_green=True)
    _single_alice(env)
    env._set_dependency_state("service:file_share", DEGRADED, "test_file_share_degraded")
    env.green_task(0)
    env.defender("rollback", {"target": "file_share"})
    env.schedule(5, lambda: env.green_task(1))
    score = env.run(12)

    assert score["mission_tasks_failed"] == 1
    assert score["mission_tasks_completed"] == 1
    events = load_trace(tmp_path / "recovery.jsonl")
    states = [e for e in events if e["type"] == "dependency_state_changed" and e["payload"]["ref"] == "file_share"]
    assert any(e["payload"]["status"] == DEGRADED for e in states)
    assert any(e["payload"]["status"] == AVAILABLE for e in states)


def test_broad_containment_improves_security_but_worsens_mission(tmp_path: Path):
    base = dict(
        seed=7,
        until=60,
        no_persistence=False,
        no_green=False,
        magic_observations=False,
        service_url=None,
        llm_cache=tmp_path / "llm",
        green_actor="scripted",
        attacker_actor="scripted",
        defender_actor="baseline",
    )
    do_nothing = run_episode(Namespace(**base, trace=tmp_path / "do-nothing.jsonl", defender="do_nothing"))
    isolate = run_episode(Namespace(**base, trace=tmp_path / "isolate.jsonl", defender="isolate_everything"))

    assert isolate["attacker_dwell_minutes"] < do_nothing["attacker_dwell_minutes"]
    assert isolate["overall_security_score"] > do_nothing["overall_security_score"]
    assert isolate["overall_mission_score"] < do_nothing["overall_mission_score"]


def test_attacker_induced_degradation_changes_mission_and_security_score(tmp_path: Path):
    no_disruption = MissionDeskEnv(tmp_path / "no-disruption.jsonl", seed=1, no_green=True)
    _single_alice(no_disruption)
    no_disruption.green_task(0)
    no_disruption_score = no_disruption.run(30)

    disrupted = MissionDeskEnv(tmp_path / "attacker-disruption.jsonl", seed=1, no_green=True)
    _single_alice(disrupted)
    disrupted.attacker("attempt_credential_access")
    disrupted.schedule(7, lambda: disrupted.attacker("lateral_move"))
    disrupted.schedule(13, lambda: disrupted.attacker("collect"))
    disrupted.schedule(20, lambda: disrupted.green_task(0))
    disrupted_score = disrupted.run(30)

    assert disrupted_score["service_disruption_count"] > no_disruption_score["service_disruption_count"]
    assert disrupted_score["mission_tasks_failed"] == 1
    assert disrupted_score["overall_mission_score"] < no_disruption_score["overall_mission_score"]
    assert disrupted_score["overall_security_score"] < no_disruption_score["overall_security_score"]


def test_score_evidence_cites_dependency_events(tmp_path: Path):
    env = MissionDeskEnv(tmp_path / "evidence.jsonl", seed=1, no_green=True)
    env._set_dependency_state("service:file_share", UNAVAILABLE, "test_file_share_unavailable")
    score = env.run(5)
    events = load_trace(tmp_path / "evidence.jsonl")
    snap = [e for e in events if e["type"] == "score_snapshot"][-1]["payload"]
    assert score["service_downtime_minutes"] > 0
    service_evidence = set(snap["evidence"]["service_downtime_minutes"])
    assert any(e["type"] == "dependency_state_changed" and e["event_id"] in service_evidence for e in events)


def test_dependency_truth_does_not_leak_to_attacker_or_green(tmp_path: Path):
    env = MissionDeskEnv(tmp_path / "observations.jsonl", seed=1, no_green=True)
    _single_alice(env)
    env._set_dependency_state("service:file_share", DEGRADED, "test_file_share_degraded")
    env.attacker("scan_network")
    env.green_task(0)
    env.run(10)
    events = load_trace(tmp_path / "observations.jsonl")

    defender = env.defender_observation()
    assert defender["service_inventory"]

    assert "depends_on" not in str(attacker_view(events))
    assert "service:file_share" not in str(attacker_view(events))
    assert "depends_on" not in str(green_view(events))
    assert "dependency_status" not in str(green_view(events))
    assert "file_share" not in str(green_view(events))
    assert "mission_app" not in str(green_view(events))


def test_defender_observation_uses_artifacts_not_raw_dependency_events(tmp_path: Path):
    env = MissionDeskEnv(tmp_path / "defender-artifacts.jsonl", seed=1, no_green=True)
    _single_alice(env)
    env._set_dependency_state("service:file_share", DEGRADED, "test_file_share_degraded")
    env.green_task(0)
    env.run(5)

    obs = defender_view(load_trace(tmp_path / "defender-artifacts.jsonl"))
    assert obs["telemetry"]
    assert not obs["service_health"]
    assert "service:file_share" not in str(obs)
    assert "dependency_state_changed" not in str(obs)


def test_degraded_dependency_reason_is_not_mislabelled_service_isolated(tmp_path: Path):
    env = MissionDeskEnv(tmp_path / "reason.jsonl", seed=1, no_green=True)
    _single_alice(env)
    env._set_dependency_state("service:file_share", DEGRADED, "test_file_share_degraded")
    env.green_task(0)
    env.run(5)

    service_events = [
        e["payload"]["ecs"]
        for e in load_trace(tmp_path / "reason.jsonl")
        if e["type"] == "telemetry_emitted"
        and e["payload"].get("category") == "service"
        and e["payload"]["ecs"].get("event.action") == "mission_task"
    ]
    assert [event["event.reason"] for event in service_events].count("dependency_degraded") == 1
    assert "service_isolated" not in [event["event.reason"] for event in service_events]
