from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from badlands.agents.campaign_memory import CampaignMemoryStore, MemoryFact, assert_no_forbidden_memory
from badlands.agents.llm import _estimate_tokens

DEFAULT_CONTEXT_TOKENS = 32768


@dataclass(frozen=True)
class CompactionThresholds:
    warning_ratio: float = 0.70
    compaction_ratio: float = 0.85
    hard_stop_ratio: float = 0.95

    def __post_init__(self) -> None:
        if not 0 < self.warning_ratio < self.compaction_ratio < self.hard_stop_ratio < 1:
            raise ValueError("compaction thresholds must satisfy 0 < warning < compaction < hard_stop < 1")

    def as_dict(self) -> dict[str, float]:
        return {
            "warning_ratio": self.warning_ratio,
            "compaction_ratio": self.compaction_ratio,
            "hard_stop_ratio": self.hard_stop_ratio,
        }


@dataclass(frozen=True)
class RoleTokenPressure:
    role: str
    token_estimate: int
    context_limit: int
    pressure: float
    state: str
    thresholds: CompactionThresholds = field(repr=False)

    def as_report(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "token_estimate": self.token_estimate,
            "context_limit": self.context_limit,
            "pressure": self.pressure,
            "state": self.state,
            "thresholds": self.thresholds.as_dict(),
        }


@dataclass
class CampaignMemoryCompaction:
    role: str
    campaign_step: int
    compaction_mode: str
    token_before: int
    token_after: int
    pressure_before: float
    pressure_after: float
    context_limit: int
    compacted_fact_count: int
    preserved_head_count: int
    preserved_recent_count: int
    source_event_ids: list[str]
    compacted_summary: str
    trace_event_id: str | None = None

    def as_report(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "campaign_step": self.campaign_step,
            "compaction_mode": self.compaction_mode,
            "token_before": self.token_before,
            "token_after": self.token_after,
            "pressure_before": self.pressure_before,
            "pressure_after": self.pressure_after,
            "context_limit": self.context_limit,
            "compacted_fact_count": self.compacted_fact_count,
            "preserved_head_count": self.preserved_head_count,
            "preserved_recent_count": self.preserved_recent_count,
            "source_event_ids": self.source_event_ids,
            "compacted_summary": self.compacted_summary,
            "trace_event_id": self.trace_event_id,
        }


def context_limit_for_role(
    role: str,
    *,
    advertised_context_tokens_by_role: dict[str, Any] | None = None,
    served_context_tokens_by_role: dict[str, Any] | None = None,
    default_context_tokens: int = DEFAULT_CONTEXT_TOKENS,
) -> int:
    for source in (served_context_tokens_by_role or {}, advertised_context_tokens_by_role or {}):
        value = source.get(role)
        if isinstance(value, int) and value > 0:
            return value
    return default_context_tokens


def role_memory_token_pressure(
    role: str,
    memory: dict[str, Any],
    *,
    context_limit: int,
    thresholds: CompactionThresholds,
) -> RoleTokenPressure:
    tokens = _estimate_tokens(json.dumps(memory, sort_keys=True))
    pressure = round(tokens / max(1, context_limit), 6)
    if pressure >= thresholds.hard_stop_ratio:
        state = "hard_stop"
    elif pressure >= thresholds.compaction_ratio:
        state = "compact"
    elif pressure >= thresholds.warning_ratio:
        state = "warning"
    else:
        state = "ok"
    return RoleTokenPressure(
        role=role,
        token_estimate=tokens,
        context_limit=context_limit,
        pressure=pressure,
        state=state,
        thresholds=thresholds,
    )


def compact_role_campaign_memory(
    store: CampaignMemoryStore,
    role: str,
    *,
    step: int,
    context_limit: int,
    thresholds: CompactionThresholds,
    preserve_head: int = 1,
    preserve_recent: int = 2,
) -> tuple[RoleTokenPressure, RoleTokenPressure, CampaignMemoryCompaction | None]:
    before_memory = store.observation_memory(role, step=step)
    assert_no_forbidden_memory(before_memory)
    before = role_memory_token_pressure(role, before_memory, context_limit=context_limit, thresholds=thresholds)
    if before.pressure < thresholds.compaction_ratio:
        return before, before, None

    role_facts = store.facts.get(role, [])
    visible_facts = [fact for fact in role_facts if fact.visible_at_step <= step]
    future_facts = [fact for fact in role_facts if fact.visible_at_step > step]
    if len(visible_facts) <= preserve_head + preserve_recent:
        if before.pressure >= thresholds.hard_stop_ratio:
            raise RuntimeError(
                f"{role} campaign memory exceeded hard-stop pressure without compactable middle history: "
                f"{before.token_estimate}/{before.context_limit}"
            )
        return before, before, None

    head = visible_facts[:preserve_head] if preserve_head else []
    tail = visible_facts[-preserve_recent:] if preserve_recent else []
    middle_start = len(head)
    middle_end = len(visible_facts) - len(tail)
    middle = visible_facts[middle_start:middle_end]
    if not middle:
        return before, before, None

    summary_fact = _summarize_middle_facts(role, middle, visible_at_step=step)
    rebuilt = [*head, summary_fact, *tail, *future_facts]
    store.facts[role] = rebuilt

    after_memory = store.observation_memory(role, step=step)
    assert_no_forbidden_memory(after_memory)
    after = role_memory_token_pressure(role, after_memory, context_limit=context_limit, thresholds=thresholds)
    if after.pressure >= thresholds.hard_stop_ratio:
        raise RuntimeError(
            f"{role} campaign memory remained above hard-stop pressure after compaction: "
            f"{after.token_estimate}/{after.context_limit}"
        )

    record = CampaignMemoryCompaction(
        role=role,
        campaign_step=step,
        compaction_mode="evidence-preserving-summary",
        token_before=before.token_estimate,
        token_after=after.token_estimate,
        pressure_before=before.pressure,
        pressure_after=after.pressure,
        context_limit=context_limit,
        compacted_fact_count=len(middle),
        preserved_head_count=len(head),
        preserved_recent_count=len(tail),
        source_event_ids=summary_fact.source_event_ids,
        compacted_summary=summary_fact.summary,
    )
    return before, after, record


def _summarize_middle_facts(role: str, facts: list[MemoryFact], *, visible_at_step: int) -> MemoryFact:
    source_event_ids = sorted({event_id for fact in facts for event_id in fact.source_event_ids})
    decision_ids = [fact.decision_event_id for fact in facts if fact.decision_event_id]
    action_counts: dict[str, int] = {}
    snippets: list[str] = []
    for fact in facts:
        action = fact.action or "unknown_action"
        action_counts[action] = action_counts.get(action, 0) + 1
        text = " ".join(fact.summary.split())
        snippets.append(f"{action}: {text[:80]}")

    action_summary = ", ".join(f"{action} x{count}" for action, count in sorted(action_counts.items()))
    summary = (
        f"Compacted {role} role-visible campaign history from {len(facts)} older facts. "
        f"Actions: {action_summary}. Evidence-linked notes: {' | '.join(snippets[:3])[:300]}"
    )
    payload = {
        "role": role,
        "summary": summary,
        "source_event_ids": source_event_ids,
        "compacted_decision_event_ids": decision_ids,
    }
    assert_no_forbidden_memory(payload)
    return MemoryFact(
        role=role,
        visible_at_step=visible_at_step,
        source_event_ids=source_event_ids,
        summary=summary,
        action="compacted_campaign_memory",
        decision_event_id=None,
        source_trace_path=None,
        compacted=True,
        compacted_from_event_ids=source_event_ids,
    )
