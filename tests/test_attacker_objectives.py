from __future__ import annotations

from pathlib import Path

from badlands.core.env import MissionDeskEnv
from badlands.core.state import initial_state
from badlands.core.trace import load_trace
from badlands.scoring.replay import derive_scores


def _objective_path(env: MissionDeskEnv) -> dict:
    env.attacker("attempt_credential_access")
    env.schedule(7, lambda: env.attacker("lateral_move"))
    env.schedule(13, lambda: env.attacker("collect"))
    env.schedule(20, lambda: env.attacker("exfiltrate"))
    env.schedule(28, lambda: env.attacker("disrupt_service", {"service_id": "mission_app"}))
    return env.run(45)


def _events(path: Path, event_type: str | None = None) -> list[dict]:
    events = load_trace(path)
    if event_type is None:
        return events
    return [event for event in events if event["type"] == event_type]


def _enable_green_users(env: MissionDeskEnv) -> None:
    restored = initial_state(seed=env.state.seed)
    env.state.users = restored.users
    env.state.auth_affinities = restored.auth_affinities


def test_objective_path_requires_prerequisites_and_scores_from_trace(tmp_path: Path):
    trace = tmp_path / "objective-path.jsonl"
    env = MissionDeskEnv(trace, seed=7, no_green=True)
    score = _objective_path(env)
    events = _events(trace)
    impacts = [event for event in events if event["type"] == "security_impact_event"]
    impact_kinds = {event["payload"].get("kind") for event in impacts}

    assert {"collection", "exfiltration", "service_disruption"} <= impact_kinds
    assert score == derive_scores(events)
    assert score["sensitive_files_accessed_count"] == 1
    assert score["exfiltration_units"] == 5
    assert score["service_disruption_count"] >= 2

    snapshot = [event for event in events if event["type"] == "score_snapshot"][-1]["payload"]
    for field in ("sensitive_files_accessed_count", "exfiltration_units", "service_disruption_count"):
        assert snapshot["evidence"][field]

    exfil_telemetry = [
        event
        for event in events
        if event["type"] == "telemetry_emitted" and event["payload"].get("category") == "exfiltration"
    ]
    assert exfil_telemetry[-1]["payload"]["ecs"]["destination.domain"] == "contained-sink.badlands.local"


def test_attacker_objectives_are_blocked_without_prerequisites(tmp_path: Path):
    trace = tmp_path / "blocked.jsonl"
    env = MissionDeskEnv(trace, seed=7, no_green=True)
    env.attacker("collect")
    env.schedule(7, lambda: env.attacker("exfiltrate"))
    env.schedule(15, lambda: env.attacker("disrupt_service", {"service_id": "mission_app"}))
    score = env.run(30)
    events = _events(trace)
    completions = [
        event
        for event in events
        if event["type"] == "action_completed" and event.get("agent") == "attacker"
    ]

    assert [event["payload"]["success"] for event in completions] == [False, False, False]
    assert score["sensitive_files_accessed_count"] == 0
    assert score["exfiltration_units"] == 0
    assert score["service_disruption_count"] == 0


def test_defender_timing_blocks_exfiltration(tmp_path: Path):
    trace = tmp_path / "contained-before-exfil.jsonl"
    env = MissionDeskEnv(trace, seed=7, no_green=True)
    env.attacker("attempt_credential_access")
    env.schedule(7, lambda: env.attacker("lateral_move"))
    env.schedule(13, lambda: env.attacker("collect"))
    env.schedule(19, lambda: env.defender("isolate_host", {"host_id": "files-1"}))
    env.schedule(21, lambda: env.attacker("exfiltrate"))
    score = env.run(35)
    events = _events(trace)
    exfil_done = [
        event
        for event in events
        if event["type"] == "action_completed" and event.get("agent") == "attacker" and event["payload"].get("action") == "exfiltrate"
    ][-1]

    assert exfil_done["payload"]["success"] is False
    assert score["sensitive_files_accessed_count"] == 1
    assert score["exfiltration_units"] == 0


def test_exfiltration_rejects_non_contained_egress(tmp_path: Path):
    trace = tmp_path / "evil-egress.jsonl"
    env = MissionDeskEnv(trace, seed=7, no_green=True)
    env.attacker("attempt_credential_access")
    env.schedule(7, lambda: env.attacker("lateral_move"))
    env.schedule(13, lambda: env.attacker("collect"))
    env.schedule(20, lambda: env.attacker("exfiltrate", {"egress": "evil.example"}))
    score = env.run(35)
    events = _events(trace)
    exfil_done = [
        event
        for event in events
        if event["type"] == "action_completed" and event.get("agent") == "attacker" and event["payload"].get("action") == "exfiltrate"
    ][-1]
    exfil_telemetry = [
        event
        for event in events
        if event["type"] == "telemetry_emitted" and event["payload"].get("category") == "exfiltration"
    ][-1]

    assert exfil_done["payload"]["success"] is False
    assert score["exfiltration_units"] == 0
    assert exfil_telemetry["payload"]["ecs"]["destination.domain"] == "contained-sink.badlands.local"
    assert exfil_telemetry["payload"]["ecs"]["badlands.egress.request_allowed"] is False


def test_service_disruption_and_recovery_change_mission_outcome(tmp_path: Path):
    trace = tmp_path / "disrupt-recover.jsonl"
    env = MissionDeskEnv(trace, seed=7, no_green=True)
    _enable_green_users(env)
    _objective_path(env)
    env.green_task(0)
    env.defender("restore_host_or_service", {"target": "file_share"})
    env.defender("restore_host_or_service", {"target": "mission_app"})
    env.schedule(5, lambda: env.green_task(1))
    score = env.run(60)

    assert score["mission_tasks_failed"] == 1
    assert score["mission_tasks_completed"] == 1
