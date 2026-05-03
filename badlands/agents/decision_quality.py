from __future__ import annotations

import re
from collections import Counter
from typing import Any

from badlands.agents.llm import observation_event_ids

ROLES = ("green", "attacker", "defender")
DISRUPTIVE_DEFENDER_ACTIONS = {"isolate_host", "reset_account", "block_indicator", "kill_process"}
TEXT_FIELDS = ("intent", "rationale", "expected_effect", "risk")
EVENT_ID_RE = re.compile(r"evt_[0-9]{6}")
HIDDEN_STATE_PATTERNS = (
    re.compile(r"\bhost\s+is\s+compromised\b", re.I),
    re.compile(r"\baccount\s+is\s+compromised\b", re.I),
    re.compile(r"\buser\s+is\s+compromised\b", re.I),
    re.compile(r"\battacker\s+(?:has|is|already)\b", re.I),
    re.compile(r"\bknown\s+(?:malicious|compromised|false\s+positive|true\s+positive)\b", re.I),
    re.compile(r"\bcredential_stolen\b", re.I),
    re.compile(r"\bhost_compromised\b", re.I),
    re.compile(r"\bobjective_state\b", re.I),
    re.compile(r"\bscorer\s+truth\b", re.I),
)
BLAST_RADIUS_PATTERNS = (
    re.compile(r"\bblast\s+radius\b", re.I),
    re.compile(r"\bmission\s+(?:impact|continuity|work|task|service|risk)\b", re.I),
    re.compile(r"\buser\s+(?:impact|lockout|workflow)\b", re.I),
    re.compile(r"\bservice\s+(?:impact|downtime|disruption)\b", re.I),
)
MISSION_PATTERNS = (
    re.compile(r"\bmission\b", re.I),
    re.compile(r"\bworkflow\b", re.I),
    re.compile(r"\bdeadline\b", re.I),
    re.compile(r"\btask\b", re.I),
)
GREEN_TICKET_PATTERNS = (
    re.compile(r"\bticket\b", re.I),
    re.compile(r"\bblocked\b", re.I),
    re.compile(r"\blockout\b", re.I),
    re.compile(r"\boutage\b", re.I),
    re.compile(r"\blatency\b", re.I),
)
GREEN_SOC_PATTERNS = (
    re.compile(r"\btriage\b", re.I),
    re.compile(r"\bcontain(?:ment)?\b", re.I),
    re.compile(r"\bisolate\b", re.I),
    re.compile(r"\battacker\b", re.I),
    re.compile(r"\bcompromis(?:e|ed)\b", re.I),
    re.compile(r"\bmalware\b", re.I),
    re.compile(r"\bSOC\b"),
    re.compile(r"\balert\b", re.I),
)


def decision_quality_report(events: list[dict[str, Any]]) -> dict[str, Any]:
    per_role = {role: _empty_role_report() for role in ROLES}
    for event in events:
        if event.get("type") not in {"llm_decision", "llm_decision_invalid"}:
            continue
        role = _event_role(event)
        if role not in per_role:
            per_role[role] = _empty_role_report()
        _ingest_decision(per_role[role], event, role)
    for role, report in per_role.items():
        _finalize_role_report(report, role)
    all_flags = [
        flag
        for role_report in per_role.values()
        for flag in role_report["role_specific_flags"]
        + role_report["repeated_actions"]
        + role_report["unsupported_evidence_ids"]
        + role_report["suspected_hidden_state_claims"]
    ]
    return {
        "rubric_version": "ds27-role-output-rubric-v1",
        "rubric_reference": "built-in role-output heuristics",
        "scope": "descriptive trace-derived heuristics for reviewer inspection; not an automatic intelligence pass/fail grade",
        "per_role": per_role,
        "all_flags": all_flags,
    }


def _empty_role_report() -> dict[str, Any]:
    return {
        "action_sequence": [],
        "evidence_ids_cited": 0,
        "observation_ids_available": 0,
        "repeated_actions": [],
        "unsupported_evidence_ids": [],
        "suspected_hidden_state_claims": [],
        "role_specific_flags": [],
        "disruptive_actions": [],
        "overreaction_flags": [],
        "blast_radius_mentions": [],
        "mission_awareness_mentions": [],
        "ticket_or_blockage_mentions": [],
        "soc_like_flags": [],
    }


def _ingest_decision(report: dict[str, Any], event: dict[str, Any], role: str) -> None:
    payload = event.get("payload", {})
    raw = payload.get("raw_decision", {})
    if not isinstance(raw, dict):
        raw = {}
    action = _decision_value(payload, raw, "action")
    event_id = str(event.get("event_id", ""))
    report["action_sequence"].append(
        {
            "event_id": event_id,
            "event_type": event.get("type"),
            "timestamp": event.get("timestamp"),
            "action": action,
            "intent": _decision_value(payload, raw, "intent"),
        }
    )
    cited = _evidence_ids(payload, raw)
    available = _available_observation_ids(payload)
    report["evidence_ids_cited"] += len(cited)
    report["observation_ids_available"] += len(available)
    for evidence_id in sorted(set(cited) - available):
        report["unsupported_evidence_ids"].append(
            _flag(event, role, "unsupported_evidence_id", "evidence_ids", evidence_id, "cited id is not present in the role observation")
        )
    for evidence_id in _ids_from_invalid_reason(payload.get("reason")):
        if evidence_id not in {flag["matched_text"] for flag in report["unsupported_evidence_ids"]}:
            report["unsupported_evidence_ids"].append(
                _flag(event, role, "unsupported_evidence_id", "reason", evidence_id, "validator rejected an evidence id not present in observation")
            )
    include_raw_output = event.get("type") == "llm_decision_invalid"
    _flag_hidden_state_claims(report, event, role, payload, raw, include_raw_output=include_raw_output)
    _flag_role_specific(report, event, role, action, payload, raw, cited)


def _finalize_role_report(report: dict[str, Any], role: str) -> None:
    actions = [item["action"] for item in report["action_sequence"] if item.get("action")]
    counts = Counter(actions)
    for action, count in sorted(counts.items()):
        if count >= 3 or (role == "attacker" and count >= 2):
            matching_events = [item["event_id"] for item in report["action_sequence"] if item.get("action") == action]
            report["repeated_actions"].append(
                {
                    "role": role,
                    "kind": "repeated_action",
                    "action": action,
                    "count": count,
                    "event_ids": matching_events,
                    "reason": "same action appears repeatedly in the live decision sequence",
                }
            )
    for key in ("blast_radius_mentions", "mission_awareness_mentions", "ticket_or_blockage_mentions"):
        report[key] = _dedupe_flags(report[key])
    for key in ("repeated_actions", "unsupported_evidence_ids", "suspected_hidden_state_claims", "role_specific_flags"):
        report[key] = _dedupe_flags(report[key])


def _flag_role_specific(
    report: dict[str, Any],
    event: dict[str, Any],
    role: str,
    action: str | None,
    payload: dict[str, Any],
    raw: dict[str, Any],
    cited: list[str],
) -> None:
    include_raw_output = event.get("type") == "llm_decision_invalid"
    text = _decision_text(payload, raw, include_raw_output=include_raw_output)
    if role == "defender":
        if action in DISRUPTIVE_DEFENDER_ACTIONS:
            report["disruptive_actions"].append({"event_id": event.get("event_id"), "action": action})
            if not cited and not _contains_any(text, BLAST_RADIUS_PATTERNS):
                flag = _flag(
                    event,
                    role,
                    "defender_overreaction",
                    "action",
                    str(action),
                    "disruptive defender action lacks cited evidence and blast-radius or mission-continuity language",
                )
                report["overreaction_flags"].append(flag)
                report["role_specific_flags"].append(flag)
        for field, value in _text_field_values(payload, raw, include_raw_output=include_raw_output):
            if match := _first_match(value, BLAST_RADIUS_PATTERNS):
                report["blast_radius_mentions"].append(_flag(event, role, "blast_radius_mention", field, match, "defender names operational blast radius or mission continuity"))
            if match := _first_match(value, MISSION_PATTERNS):
                report["mission_awareness_mentions"].append(_flag(event, role, "mission_awareness_mention", field, match, "defender references mission or workflow impact"))
    elif role == "green":
        for field, value in _text_field_values(payload, raw, include_raw_output=include_raw_output):
            if match := _first_match(value, GREEN_SOC_PATTERNS):
                flag = _flag(event, role, "green_soc_like_behavior", field, match, "green user used security-analyst language outside the role contract")
                report["soc_like_flags"].append(flag)
                report["role_specific_flags"].append(flag)
            if match := _first_match(value, MISSION_PATTERNS):
                report["mission_awareness_mentions"].append(_flag(event, role, "mission_awareness_mention", field, match, "green user references mission task context"))
            if match := _first_match(value, GREEN_TICKET_PATTERNS):
                report["ticket_or_blockage_mentions"].append(_flag(event, role, "ticket_or_blockage_mention", field, match, "green user describes user-visible blockage or ticket behavior"))
    elif role == "attacker":
        for field, value in _text_field_values(payload, raw, include_raw_output=include_raw_output):
            if match := _first_match(value, (re.compile(r"\bexfiltrat", re.I), re.compile(r"\bcollect", re.I), re.compile(r"\blateral", re.I))):
                report["role_specific_flags"].append(_flag(event, role, "attacker_objective_language", field, match, "attacker names an objective-oriented step"))


def _flag_hidden_state_claims(
    report: dict[str, Any],
    event: dict[str, Any],
    role: str,
    payload: dict[str, Any],
    raw: dict[str, Any],
    *,
    include_raw_output: bool,
) -> None:
    for field, value in _text_field_values(payload, raw, include_raw_output=include_raw_output):
        if match := _first_match(value, HIDDEN_STATE_PATTERNS):
            report["suspected_hidden_state_claims"].append(
                _flag(event, role, "suspected_hidden_state_claim", field, match, "decision asserts hidden compromise, scorer, or ground-truth state")
            )


def _event_role(event: dict[str, Any]) -> str:
    payload = event.get("payload", {})
    return str(event.get("agent") or payload.get("role") or "unknown")


def _decision_value(payload: dict[str, Any], raw: dict[str, Any], key: str) -> str | None:
    value = raw.get(key, payload.get(key))
    return str(value) if value is not None else None


def _decision_text(payload: dict[str, Any], raw: dict[str, Any], *, include_raw_output: bool) -> str:
    return " ".join(value for _, value in _text_field_values(payload, raw, include_raw_output=include_raw_output))


def _text_field_values(payload: dict[str, Any], raw: dict[str, Any], *, include_raw_output: bool) -> list[tuple[str, str]]:
    values = []
    for field in TEXT_FIELDS:
        value = raw.get(field, payload.get(field))
        if isinstance(value, str) and value.strip():
            values.append((field, value))
    reason = payload.get("reason")
    if isinstance(reason, str) and reason.strip():
        values.append(("reason", reason))
    if include_raw_output:
        for output in _raw_outputs(payload, raw):
            content = output.get("content") if isinstance(output, dict) else None
            if isinstance(content, str) and content.strip():
                values.append(("raw_output", content))
    return values


def _raw_outputs(payload: dict[str, Any], raw: dict[str, Any]) -> list[dict[str, Any]]:
    raw_outputs = raw.get("raw_outputs") or payload.get("inference_telemetry", {}).get("raw_outputs") or []
    return raw_outputs if isinstance(raw_outputs, list) else []


def _evidence_ids(payload: dict[str, Any], raw: dict[str, Any]) -> list[str]:
    value = raw.get("evidence_ids", payload.get("evidence_ids", []))
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _available_observation_ids(payload: dict[str, Any]) -> set[str]:
    ids = payload.get("observation_event_ids")
    if isinstance(ids, list):
        return {item for item in ids if isinstance(item, str)}
    return observation_event_ids(payload.get("observation", {}))


def _ids_from_invalid_reason(reason: object) -> list[str]:
    if not isinstance(reason, str):
        return []
    return EVENT_ID_RE.findall(reason)


def _contains_any(text: str, patterns: tuple[re.Pattern[str], ...]) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def _first_match(text: str, patterns: tuple[re.Pattern[str], ...]) -> str | None:
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


def _flag(event: dict[str, Any], role: str, kind: str, field: str, matched_text: str, reason: str) -> dict[str, Any]:
    return {
        "event_id": event.get("event_id"),
        "role": role,
        "kind": kind,
        "field": field,
        "matched_text": matched_text,
        "reason": reason,
    }


def _dedupe_flags(flags: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for flag in flags:
        key = repr(sorted(flag.items()))
        if key in seen:
            continue
        seen.add(key)
        out.append(flag)
    return out
