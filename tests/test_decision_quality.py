from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from badlands.agents.decision_quality import decision_quality_report
from badlands.core.env import MissionDeskEnv
from badlands.core.trace import load_trace
from badlands.live_validate import RoleEndpoint, build_report
from badlands.scoring.replay import derive_scores


def _decision_event(
    *,
    event_id: str,
    role: str,
    action: str,
    evidence_ids: list[str] | None = None,
    observation_event_ids: list[str] | None = None,
    rationale: str = "Visible evidence supports this step.",
    expected_effect: str = "The action should progress the role objective.",
    risk: str = "The evidence may be incomplete.",
) -> dict:
    return {
        "event_id": event_id,
        "type": "llm_decision",
        "timestamp": int(event_id.removeprefix("evt_")),
        "agent": role,
        "parents": evidence_ids or [],
        "payload": {
            "role": role,
            "observation": {"items": [{"event_id": item} for item in (observation_event_ids or [])]},
            "observation_event_ids": observation_event_ids or [],
            "raw_decision": {
                "intent": "act",
                "action": action,
                "parameters": {},
                "confidence": 0.7,
                "evidence_ids": evidence_ids or [],
                "rationale": rationale,
                "expected_effect": expected_effect,
                "risk": risk,
            },
            "intent": "act",
            "action": action,
            "parameters": {},
            "confidence": 0.7,
            "evidence_ids": evidence_ids or [],
            "rationale": rationale,
            "expected_effect": expected_effect,
            "risk": risk,
            "inference_telemetry": {},
        },
    }


def test_flags_repeated_attacker_actions():
    events = [
        _decision_event(event_id="evt_000001", role="attacker", action="scan_network"),
        _decision_event(event_id="evt_000002", role="attacker", action="scan_network"),
        _decision_event(event_id="evt_000003", role="attacker", action="scan_network"),
    ]
    report = decision_quality_report(events)
    repeats = report["per_role"]["attacker"]["repeated_actions"]
    assert repeats[0]["kind"] == "repeated_action"
    assert repeats[0]["action"] == "scan_network"
    assert repeats[0]["count"] == 3


def test_flags_defender_overreaction_without_blast_radius_or_evidence():
    events = [
        _decision_event(
            event_id="evt_000010",
            role="defender",
            action="isolate_host",
            evidence_ids=[],
            rationale="The host is suspicious, so isolation is safest.",
            risk="Low risk.",
        )
    ]
    report = decision_quality_report(events)
    overreactions = report["per_role"]["defender"]["overreaction_flags"]
    assert overreactions[0]["kind"] == "defender_overreaction"
    assert overreactions[0]["matched_text"] == "isolate_host"


def test_flags_green_soc_like_behavior():
    events = [
        _decision_event(
            event_id="evt_000020",
            role="green",
            action="create_ticket",
            rationale="I will triage the alert because the attacker compromised this host.",
            expected_effect="Contain the incident.",
            risk="Malware may continue.",
        )
    ]
    report = decision_quality_report(events)
    green = report["per_role"]["green"]
    assert green["soc_like_flags"]
    assert any(flag["kind"] == "green_soc_like_behavior" for flag in green["role_specific_flags"])


def test_extracts_unsupported_evidence_ids_from_invalid_decision():
    events = [
        {
            "event_id": "evt_000030",
            "type": "llm_decision_invalid",
            "timestamp": 30,
            "agent": "defender",
            "parents": [],
            "payload": {
                "role": "defender",
                "observation": {"alerts": [{"event_id": "evt_000001"}]},
                "raw_decision": {
                    "intent": "contain",
                    "action": "isolate_host",
                    "parameters": {},
                    "confidence": 0.9,
                    "evidence_ids": ["evt_999999"],
                    "rationale": "The invented event proves compromise.",
                    "expected_effect": "Isolate host.",
                    "risk": "Mission work stops.",
                },
                "reason": "evidence_ids not present in observation: evt_999999",
                "inference_telemetry": {},
            },
        }
    ]
    report = decision_quality_report(events)
    unsupported = report["per_role"]["defender"]["unsupported_evidence_ids"]
    assert unsupported[0]["matched_text"] == "evt_999999"


def test_flags_hidden_state_claims():
    events = [
        _decision_event(
            event_id="evt_000040",
            role="defender",
            action="query_endpoint",
            evidence_ids=["evt_000001"],
            observation_event_ids=["evt_000001"],
            rationale="The host is compromised and should be investigated.",
        )
    ]
    report = decision_quality_report(events)
    hidden = report["per_role"]["defender"]["suspected_hidden_state_claims"]
    assert hidden[0]["kind"] == "suspected_hidden_state_claim"
    assert hidden[0]["matched_text"] == "host is compromised"


def test_live_report_includes_decision_quality(tmp_path: Path):
    trace = tmp_path / "trace.jsonl"
    env = MissionDeskEnv(trace, seed=1, no_green=True)
    decision_id = env.trace.emit(
        "llm_decision",
        0,
        _decision_event(
            event_id="evt_000001",
            role="defender",
            action="query_endpoint",
            evidence_ids=[],
            observation_event_ids=[],
        )["payload"],
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
    assert report["decision_quality"]["rubric_version"] == "ds27-role-output-rubric-v1"
    assert report["decision_quality"]["per_role"]["defender"]["action_sequence"][0]["event_id"] == decision_id
