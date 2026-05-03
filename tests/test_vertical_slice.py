from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from badlands.cli import run_episode
from badlands.core.env import MissionDeskEnv
from badlands.core.observations import assert_no_forbidden, defender_view
from badlands.core.trace import load_trace
from badlands.scoring.replay import derive_scores


def args(tmp_path: Path, **kw):
    base = dict(trace=tmp_path / "trace.jsonl", seed=7, until=60, defender="evidence_gathering", no_persistence=False, no_green=False, no_noise=False, perfect_sensors=False, magic_observations=False, service_url=None, llm_cache=tmp_path / "llm", green_actor="scripted", attacker_actor="scripted", defender_actor="baseline")
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


def test_benign_noise_emits_trace_backed_ambiguous_alerts(tmp_path: Path):
    run_episode(args(tmp_path, trace=tmp_path / "noise.jsonl"))
    events = load_trace(tmp_path / "noise.jsonl")
    noise = [
        e for e in events
        if e["type"] == "state_transition" and e["payload"].get("kind") == "benign_noise_scheduled"
    ]
    assert {e["payload"]["noise_kind"] for e in noise} >= {"failed_auth_burst", "noisy_script", "file_access_burst"}
    alerts = [e for e in events if e["type"] == "alert_emitted"]
    assert alerts
    assert all(e["payload"]["source_event_ids"] for e in alerts)
    credential_alerts = [e for e in alerts if e["payload"]["rule_id"] == "badlands.credential_access"]
    assert len(credential_alerts) >= 2
    assert all("known_false_positive_notes" not in e["payload"] for e in credential_alerts)
    assert_no_forbidden(defender_view(events))


def test_sensor_delay_drop_and_perfect_sensor_ablation(tmp_path: Path):
    run_episode(args(tmp_path, trace=tmp_path / "default.jsonl"))
    run_episode(args(tmp_path, trace=tmp_path / "perfect.jsonl", perfect_sensors=True))
    default_events = load_trace(tmp_path / "default.jsonl")
    perfect_events = load_trace(tmp_path / "perfect.jsonl")
    default_telemetry = [e for e in default_events if e["type"] == "telemetry_emitted"]
    perfect_telemetry = [e for e in perfect_events if e["type"] == "telemetry_emitted"]
    assert any(e["payload"]["sensor"]["dropped"] for e in default_telemetry)
    assert any(e["payload"]["sensor"]["visible_at"] and e["payload"]["sensor"]["visible_at"] > e["timestamp"] for e in default_telemetry)
    assert not any(e["payload"]["sensor"]["dropped"] for e in perfect_telemetry)
    assert all(e["payload"]["sensor"]["visible_at"] == e["timestamp"] for e in perfect_telemetry)
    default_first_alert = min(e["timestamp"] for e in default_events if e["type"] == "alert_emitted")
    perfect_first_alert = min(e["timestamp"] for e in perfect_events if e["type"] == "alert_emitted")
    assert perfect_first_alert < default_first_alert


def test_no_noise_ablation_reduces_false_positive_pressure(tmp_path: Path):
    full = run_episode(args(tmp_path, trace=tmp_path / "full.jsonl"))
    no_noise = run_episode(args(tmp_path, trace=tmp_path / "no-noise.jsonl", no_noise=True))
    full_events = load_trace(tmp_path / "full.jsonl")
    no_noise_events = load_trace(tmp_path / "no-noise.jsonl")
    assert len([e for e in full_events if e["type"] == "alert_emitted"]) > len([e for e in no_noise_events if e["type"] == "alert_emitted"])
    assert full["false_positive_actions"] > no_noise["false_positive_actions"]
    assert full["analyst_minutes"] > no_noise["analyst_minutes"]


def test_defender_observation_respects_sensor_visibility(tmp_path: Path):
    env = MissionDeskEnv(tmp_path / "visibility.jsonl", seed=7)
    env.run(5)
    early = env.defender_observation()
    assert "bad_password_burst" not in str(early)
    env.run(12)
    late = env.defender_observation()
    assert "bad_password_burst" in str(late)
    assert "noise-000-failed_auth_burst" not in str(late)
    assert_no_forbidden(late)


def test_defender_observation_does_not_expose_benign_only_markers(tmp_path: Path):
    run_episode(args(tmp_path, trace=tmp_path / "leak.jsonl"))
    events = load_trace(tmp_path / "leak.jsonl")
    obs_text = str(defender_view(events))
    forbidden_markers = [
        "false_positive",
        "known_false_positive",
        "benign_noise",
        "benign_noise_scheduled",
        "noise-000",
        "noise-001",
        "badlands.alert.notes",
    ]
    assert not any(marker in obs_text for marker in forbidden_markers)


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
