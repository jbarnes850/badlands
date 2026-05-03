from __future__ import annotations

from badlands.core.attacker_actions import (
    ATTACKER_ACTION_CALIBRATION_IDS,
    ATTACKER_ACTION_DURATIONS,
    ATTACKER_ACTIONS,
)
from badlands.core.calibration import all_calibration_records, calibration_metadata, calibration_report
from badlands.core.defender_actions import (
    DEFENDER_ACTION_CALIBRATION_IDS,
    DEFENDER_ACTION_DURATIONS,
    DEFENDER_ACTIONS,
)
from badlands.core.env import MissionDeskEnv
from badlands.core.observations import assert_no_forbidden, attacker_view, defender_view
from badlands.core.trace import load_trace
from badlands.scoring.replay import derive_scores

STALE_URL = "https://github.com/dfki-in-sec/NASimEmu"


def test_calibration_records_are_schema_complete_and_safe() -> None:
    actions = set(ATTACKER_ACTIONS) | set(DEFENDER_ACTIONS)
    ids = set()
    for record in all_calibration_records():
        assert record.id not in ids
        ids.add(record.id)
        assert record.action in actions
        assert record.status in {"calibrated", "heuristic", "unvalidated"}
        assert record.confidence in {"low", "medium", "high"}
        assert record.source
        assert record.source_urls
        assert record.preconditions
        assert record.expected_artifacts
        assert record.duration_range[0] <= record.duration_range[1]
        assert STALE_URL not in record.source_urls
        assert record.status != "calibrated"


def test_action_specs_reference_existing_calibration_records() -> None:
    record_ids = {record.id for record in all_calibration_records()}
    referenced = ATTACKER_ACTION_CALIBRATION_IDS | DEFENDER_ACTION_CALIBRATION_IDS
    assert len(referenced) >= 3
    assert set(referenced) >= {
        "scan_network",
        "attempt_credential_access",
        "lateral_move",
        "collect",
        "isolate_host",
        "reset_account",
        "restore_host_or_service",
    }
    assert set(referenced.values()) <= record_ids


def test_duration_constants_fit_calibration_ranges() -> None:
    durations = ATTACKER_ACTION_DURATIONS | DEFENDER_ACTION_DURATIONS
    for record in all_calibration_records():
        duration = durations[record.action]
        low, high = record.duration_range
        assert low <= duration <= high


def test_calibration_report_surfaces_missing_actions() -> None:
    report = calibration_report(["scan_network", "unmodeled_action"])
    assert report["missing"] == ["unmodeled_action"]
    assert report["summary"]["records_missing"] == 1
    missing = calibration_metadata("unmodeled_action", applied_duration=4)
    assert missing["status"] == "unvalidated"
    assert missing["warnings"] == ["missing_calibration_record"]


def test_action_started_trace_carries_calibration_metadata(tmp_path) -> None:
    env = MissionDeskEnv(tmp_path / "calibration.jsonl", seed=7, no_green=True)
    env.attacker("scan_network")
    env.defender("reset_account", {"user_id": "alice"})
    env.run(10)

    events = load_trace(tmp_path / "calibration.jsonl")
    started = [
        event["payload"]
        for event in events
        if event["type"] == "action_started"
        and event["payload"]["action"] in {"scan_network", "reset_account"}
    ]
    assert {payload["action"] for payload in started} == {"scan_network", "reset_account"}
    for payload in started:
        calibration = payload["calibration"]
        assert calibration["record_id"]
        assert calibration["status"] == "heuristic"
        assert calibration["warnings"] == ["heuristic_calibration_not_validated"]
        assert calibration["applied_duration"] == payload["duration"]
        assert calibration["expected_artifacts"]
        assert calibration["preconditions"]

    assert derive_scores(events)
    assert_no_forbidden(attacker_view(events))
    assert_no_forbidden(defender_view(events))


def test_missing_calibration_trace_warning_is_explicit(tmp_path) -> None:
    env = MissionDeskEnv(tmp_path / "missing-calibration.jsonl", seed=1, no_green=True)
    env.request("defender", "unmodeled_action", {}, 1, lambda _parent: None)
    env.run(2)

    events = load_trace(tmp_path / "missing-calibration.jsonl")
    started = [event for event in events if event["type"] == "action_started"][-1]
    calibration = started["payload"]["calibration"]
    assert calibration["record_id"] is None
    assert calibration["status"] == "unvalidated"
    assert calibration["warnings"] == ["missing_calibration_record"]


def test_green_action_started_trace_carries_missing_calibration_warning(tmp_path) -> None:
    env = MissionDeskEnv(tmp_path / "green-calibration.jsonl", seed=7)
    env.green_task(0, selected_action="use_mission_app")
    env.run(1)

    events = load_trace(tmp_path / "green-calibration.jsonl")
    started = [
        event for event in events
        if event["type"] == "action_started" and event.get("agent") == "green"
    ][-1]
    calibration = started["payload"]["calibration"]
    assert calibration["record_id"] is None
    assert calibration["status"] == "unvalidated"
    assert calibration["warnings"] == ["missing_calibration_record"]
    assert calibration["applied_duration"] == 0
