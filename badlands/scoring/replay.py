from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from badlands.core.trace import load_trace

FIELDS = [
    "mission_tasks_completed", "mission_tasks_failed", "service_downtime_minutes",
    "user_lockout_minutes", "host_isolation_minutes", "benign_process_kills",
    "attacker_dwell_minutes", "persistence_minutes", "credentials_compromised_count",
    "lateral_movement_count", "sensitive_files_accessed_count", "exfiltration_units",
    "service_disruption_count",
    "true_positive_actions", "false_positive_actions", "analyst_minutes", "action_count", "escalation_count",
]


def _add(score: dict[str, int], evidence: dict[str, list[str]], field: str, event: dict, amount: int = 1) -> None:
    score[field] += amount
    evidence[field].append(event["event_id"])
    evidence[field].extend(event["payload"].get("source_event_ids", []))


def derive_scores_with_evidence(events: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, list[str]]]:
    score = {k: 0 for k in FIELDS}
    evidence: dict[str, list[str]] = {k: [] for k in FIELDS}
    first_compromise: int | None = None
    first_persistence: int | None = None
    containment_time: int | None = None
    persistence_end: int | None = None
    creds: set[str] = set()
    impacted_hosts: set[str] = set()
    impacted_users: set[str] = set()
    evidence_events = [ev for ev in events if ev["type"] != "score_snapshot"]

    for event in evidence_events:
        payload = event["payload"]
        event_type = event["type"]
        if event_type == "mission_task_event":
            if payload.get("status") == "completed":
                _add(score, evidence, "mission_tasks_completed", event)
            if payload.get("status") == "failed":
                _add(score, evidence, "mission_tasks_failed", event)
        elif event_type == "defense_harm_event":
            _add(score, evidence, payload.get("field", "service_downtime_minutes"), event, int(payload.get("minutes", 0)))
        elif event_type == "security_impact_event":
            kind = payload.get("kind")
            if kind == "compromise_active":
                first_compromise = event["timestamp"] if first_compromise is None else first_compromise
                impacted_hosts.add(payload.get("host_ref", ""))
                evidence["attacker_dwell_minutes"].append(event["event_id"])
            elif kind == "persistence_active":
                first_persistence = event["timestamp"] if first_persistence is None else first_persistence
                impacted_hosts.add(payload.get("host_ref", ""))
                evidence["persistence_minutes"].append(event["event_id"])
            elif kind == "persistence_removed":
                persistence_end = event["timestamp"] if persistence_end is None else min(persistence_end, event["timestamp"])
                evidence["persistence_minutes"].append(event["event_id"])
            elif kind == "credential_compromised":
                creds.add(payload.get("user"))
                impacted_users.add(payload.get("user", ""))
                evidence["credentials_compromised_count"].append(event["event_id"])
            elif kind == "lateral_movement":
                _add(score, evidence, "lateral_movement_count", event)
                impacted_hosts.add(payload.get("dst", ""))
            elif kind == "collection":
                _add(score, evidence, "sensitive_files_accessed_count", event)
            elif kind == "exfiltration":
                _add(score, evidence, "exfiltration_units", event, int(payload.get("units", 1)))
            elif kind == "service_disruption":
                _add(score, evidence, "service_disruption_count", event)
        elif event_type == "action_completed" and event.get("agent") == "defender":
            _add(score, evidence, "action_count", event)
            _add(score, evidence, "analyst_minutes", event, int(payload.get("duration", 0)))
            action = payload.get("action")
            target = payload.get("host_id") or payload.get("user_id") or payload.get("target")
            true_from_evidence = (action == "isolate_host" and target in impacted_hosts) or (
                action == "reset_account" and target in impacted_users
            ) or (
                action == "kill_process" and payload.get("process_ref") == "/tmp/.mission-updater" and payload.get("outcome") == "process terminated"
            )
            false_from_evidence = action in {"isolate_host", "reset_account"} and not true_from_evidence
            false_from_evidence = false_from_evidence or (
                action == "kill_process"
                and payload.get("outcome") == "process terminated"
                and payload.get("process_ref") != "/tmp/.mission-updater"
            )
            if action == "escalate":
                _add(score, evidence, "escalation_count", event)
            if true_from_evidence:
                _add(score, evidence, "true_positive_actions", event)
                if action == "isolate_host":
                    containment_time = event["timestamp"] if containment_time is None else min(containment_time, event["timestamp"])
                    persistence_end = event["timestamp"] if persistence_end is None else min(persistence_end, event["timestamp"])
            elif false_from_evidence:
                _add(score, evidence, "false_positive_actions", event)

    end = max((event["timestamp"] for event in evidence_events), default=0)
    if first_compromise is not None:
        score["attacker_dwell_minutes"] = max(0, (containment_time or end) - first_compromise)
    if first_persistence is not None:
        score["persistence_minutes"] = max(0, (persistence_end or end) - first_persistence)
    score["credentials_compromised_count"] = len([cred for cred in creds if cred])
    score["overall_mission_score"] = (
        score["mission_tasks_completed"] * 10
        - score["mission_tasks_failed"] * 10
        - score["user_lockout_minutes"]
        - score["host_isolation_minutes"]
        - score["service_downtime_minutes"]
    )
    score["overall_security_score"] = (
        100
        - score["attacker_dwell_minutes"]
        - 10 * score["lateral_movement_count"]
        - 20 * score["sensitive_files_accessed_count"]
        - 5 * score["exfiltration_units"]
        - 10 * score["service_disruption_count"]
    )
    score["overall_defense_quality_score"] = score["true_positive_actions"] * 10 - score["false_positive_actions"] * 10 - score["analyst_minutes"]
    for aggregate in ["overall_mission_score", "overall_security_score", "overall_defense_quality_score"]:
        evidence[aggregate] = sorted({eid for ids in evidence.values() for eid in ids})
    return score, evidence


def derive_scores(events: list[dict[str, Any]]) -> dict[str, Any]:
    return derive_scores_with_evidence(events)[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", type=Path)
    args = parser.parse_args()
    print(json.dumps(derive_scores(load_trace(args.trace)), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
