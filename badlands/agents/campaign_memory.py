from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


FORBIDDEN_MEMORY_KEYS = {
    "score",
    "score_snapshot",
    "scorer",
    "true_positive",
    "false_positive",
    "host_compromised",
    "objective_state",
    "future_schedule",
    "attacker_location",
    "privileged_service_truth",
}


@dataclass(frozen=True)
class MemoryFact:
    role: str
    visible_at_step: int
    source_event_ids: list[str]
    summary: str
    action: str | None = None
    decision_event_id: str | None = None
    source_trace_path: str | None = None

    def as_observation_item(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "visible_at_step": self.visible_at_step,
            "source_event_ids": self.source_event_ids,
            "summary": self.summary,
            "action": self.action,
            "decision_event_id": self.decision_event_id,
            "source_trace_path": self.source_trace_path,
        }


@dataclass
class CampaignMemoryStore:
    facts: dict[str, list[MemoryFact]] = field(default_factory=dict)

    def add(self, fact: MemoryFact) -> None:
        self.facts.setdefault(fact.role, []).append(fact)

    def observation_memory(self, role: str, *, step: int) -> dict[str, Any]:
        role_facts = [fact for fact in self.facts.get(role, []) if fact.visible_at_step <= step]
        return {
            "mode": "role_visible_campaign_memory",
            "step": step,
            "facts": [fact.as_observation_item() for fact in role_facts],
            "source_event_ids": sorted({eid for fact in role_facts for eid in fact.source_event_ids}),
        }


def assert_no_forbidden_memory(obj: Any, *, path: str = "memory") -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_text = str(key).lower()
            if key_text in FORBIDDEN_MEMORY_KEYS or any(term in key_text for term in FORBIDDEN_MEMORY_KEYS):
                raise ValueError(f"forbidden memory key at {path}.{key}: {key}")
            assert_no_forbidden_memory(value, path=f"{path}.{key}")
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            assert_no_forbidden_memory(value, path=f"{path}[{idx}]")
    elif isinstance(obj, str):
        lowered = obj.lower()
        for term in FORBIDDEN_MEMORY_KEYS:
            if term in lowered:
                raise ValueError(f"forbidden memory text at {path}: {term}")


def memory_fact_from_decision(event: dict[str, Any], *, visible_at_step: int) -> MemoryFact:
    if event.get("type") != "llm_decision":
        raise ValueError("memory can only be extracted from valid llm_decision events")
    role = str(event.get("agent") or event["payload"].get("role"))
    payload = event["payload"]
    observation = payload.get("observation", {})
    assert_no_forbidden_memory(observation, path=f"{event['event_id']}.observation")
    evidence_ids = [eid for eid in payload.get("evidence_ids", []) if isinstance(eid, str)]
    observation_ids = [eid for eid in payload.get("observation_event_ids", []) if isinstance(eid, str)]
    source_event_ids = sorted({event["event_id"], *evidence_ids, *observation_ids})
    action = str(payload.get("action", ""))
    intent = str(payload.get("intent", "")).strip()
    rationale = str(payload.get("rationale", "")).strip()
    summary = f"Previous visible decision chose {action}: {intent or rationale}".strip()
    assert_no_forbidden_memory(
        {"summary": summary, "source_event_ids": source_event_ids},
        path=f"{event['event_id']}.memory_fact",
    )
    return MemoryFact(
        role=role,
        visible_at_step=visible_at_step,
        source_event_ids=source_event_ids,
        summary=summary,
        action=action,
        decision_event_id=event["event_id"],
    )


def add_campaign_memory(observation: dict[str, Any], memory: dict[str, Any]) -> dict[str, Any]:
    assert_no_forbidden_memory(memory)
    return {**observation, "campaign_memory": memory}
