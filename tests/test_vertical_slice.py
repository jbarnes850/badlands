from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from badlands.cli import run_episode
from badlands.core.env import MissionDeskEnv
from badlands.core.observations import assert_no_forbidden, defender_view
from badlands.core.trace import load_trace
from badlands.scoring.replay import derive_scores


def args(tmp_path: Path, **kw):
    base = dict(trace=tmp_path / "trace.jsonl", seed=7, until=60, defender="evidence_gathering", no_persistence=False, no_green=False, magic_observations=False, service_url=None, llm_cache=tmp_path / "llm", green_actor="scripted", attacker_actor="scripted", defender_actor="baseline")
    base.update(kw)
    return Namespace(**base)


def test_episode_has_required_events_and_replay(tmp_path: Path):
    score = run_episode(args(tmp_path))
    events = load_trace(tmp_path / "trace.jsonl")
    required = {"action_requested","action_started","action_completed","state_transition","telemetry_emitted","alert_emitted","observation_delivered","mission_task_event","defense_harm_event","security_impact_event","score_snapshot"}
    assert required <= {e["type"] for e in events}
    assert derive_scores(events[:-1]) == score


def test_defender_observation_does_not_leak_hidden_state(tmp_path: Path):
    run_episode(args(tmp_path))
    obs = defender_view(load_trace(tmp_path / "trace.jsonl"))
    assert_no_forbidden(obs)
    text = str(obs)
    for forbidden in ["host_compromised", "true_positive", "credential_stolen", "compromised", "scoring"]:
        assert forbidden not in text


def test_leak_guard_catches_forbidden_fields():
    try:
        assert_no_forbidden({"host_compromised": True})
    except AssertionError:
        return
    raise AssertionError("leak guard failed")


def test_timing_changes_outcome(tmp_path: Path):
    early = MissionDeskEnv(tmp_path / "early.jsonl", seed=1)
    early.attacker("attempt_credential_access")
    early.defender("reset_account", {"user_id": "bob"})
    early.run(4)
    early.run(20)

    late = MissionDeskEnv(tmp_path / "late.jsonl", seed=1)
    late.attacker("attempt_credential_access")
    late.schedule(8, lambda: late.defender("reset_account", {"user_id": "bob"}))
    late.run(20)
    assert derive_scores(load_trace(tmp_path / "early.jsonl"))["credentials_compromised_count"] <= derive_scores(load_trace(tmp_path / "late.jsonl"))["credentials_compromised_count"]


def test_ablations_directional_outcomes(tmp_path: Path):
    full = run_episode(args(tmp_path, trace=tmp_path / "full.jsonl"))
    no_persist = run_episode(args(tmp_path, trace=tmp_path / "nop.jsonl", no_persistence=True))
    no_green = run_episode(args(tmp_path, trace=tmp_path / "nogreen.jsonl", no_green=True, defender="isolate_everything"))
    isolate_full = run_episode(args(tmp_path, trace=tmp_path / "iso.jsonl", defender="isolate_everything"))
    assert full["persistence_minutes"] > no_persist["persistence_minutes"]
    assert no_green["mission_tasks_failed"] == 0
    assert isolate_full["mission_tasks_failed"] > no_green["mission_tasks_failed"]
    assert isolate_full["host_isolation_minutes"] > 0


def test_magic_observation_ablation_changes_outcome(tmp_path: Path):
    normal = run_episode(args(tmp_path, trace=tmp_path / "normal.jsonl", defender="alert_label"))
    magic = run_episode(args(tmp_path, trace=tmp_path / "magic.jsonl", defender="alert_label", magic_observations=True))
    assert magic["true_positive_actions"] > normal["true_positive_actions"]


def test_score_snapshot_has_evidence_references(tmp_path: Path):
    run_episode(args(tmp_path))
    events = load_trace(tmp_path / "trace.jsonl")
    snap = [e for e in events if e["type"] == "score_snapshot"][-1]["payload"]
    evidence = snap["evidence"]
    for field, value in snap.items():
        if field != "evidence" and isinstance(value, int) and value != 0:
            assert evidence[field]


def test_lanl_fixture_makes_auth_non_uniform(tmp_path: Path):
    run_episode(args(tmp_path, trace=tmp_path / "lanl.jsonl"))
    events = load_trace(tmp_path / "lanl.jsonl")
    auth = [e["payload"]["ecs"] for e in events if e["type"] == "telemetry_emitted" and e["payload"].get("category") == "auth"]
    assert {a["event.dataset"] for a in auth} == {"badlands.idp"}
    logins = [a for a in auth if a["event.action"] == "user_login" and a["event.outcome"] == "success"]
    assert logins
    assert len({(a["user.name"], a["source.host"]) for a in logins}) < len(logins)
