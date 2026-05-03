from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import pytest

from badlands.agents.agents_sdk import AgentsSdkCompatClient
from badlands.agents.campaign_memory import CampaignMemoryStore, MemoryFact, assert_no_forbidden_memory, memory_fact_from_decision
from badlands.agents.context_compaction import CompactionThresholds, compact_role_campaign_memory
from badlands.campaigns.agents_sdk_smoke import _compact_if_needed, run_campaign
from badlands.core.env import MissionDeskEnv
from badlands.core.trace import load_trace
from badlands.scoring.replay import derive_scores


def test_adapter_campaign_replay_and_memory_effects(tmp_path: Path) -> None:
    report = run_campaign(
        argparse.Namespace(
            seed=7,
            steps=2,
            until=40,
            out=tmp_path,
            scenario=None,
            service_url=None,
            chat_timeout=30,
            sdk_mode="adapter",
            quiet=True,
            green_base_url=None,
            green_api_key=None,
            green_model=None,
            attacker_base_url=None,
            attacker_api_key=None,
            attacker_model=None,
            defender_base_url=None,
            defender_api_key=None,
            defender_model=None,
        )
    )
    assert report["status"] == "completed"
    assert report["replay"]["ok"] is True
    assert report["canonicality"]["sdk_sessions_required_for_replay"] is False
    assert set(report["sdk_session_ids"]) == {"green", "attacker", "defender"}
    assert len(set(report["sdk_session_ids"].values())) == 3
    assert {effect["role"] for effect in report["step2_memory_effects"]} == {"green", "attacker", "defender"}
    assert report["compaction_mode"] == "evidence-preserving-summary"
    assert set(report["token_pressure_by_role"]) == {"green", "attacker", "defender"}
    assert report["compaction"]["count"] == 0
    assert report["sdk_session_strategy"] == {
        "mode": "bounded_tail_plus_campaign_memory_compaction",
        "item_limit": 12,
        "long_term_memory_source": "Badlands JSONL campaign memory",
    }

    step2 = load_trace(tmp_path / "step-2.jsonl")
    assert derive_scores(step2) == report["steps"][1]["replay_score"]
    decision_events = [event for event in step2 if event["type"] == "llm_decision"]
    for event in decision_events:
        telemetry = event["payload"]["inference_telemetry"]
        assert telemetry["sdk_session_id"] == report["sdk_session_ids"][event["agent"]]
        assert telemetry["sdk_run_id"]
        assert event["payload"]["observation"]["campaign_memory"]["source_event_id"] in event["payload"]["evidence_ids"]


def test_campaign_memory_rejects_hidden_fields() -> None:
    event = {
        "event_id": "evt_000123",
        "type": "llm_decision",
        "agent": "defender",
        "payload": {
            "role": "defender",
            "observation": {"alerts": [{"event_id": "evt_000001", "host_compromised": True}]},
            "observation_event_ids": ["evt_000001"],
            "evidence_ids": ["evt_000001"],
            "action": "query_endpoint",
            "intent": "Check host",
            "rationale": "Check visible host alert",
        },
    }
    with pytest.raises(ValueError, match="forbidden memory key"):
        memory_fact_from_decision(event, visible_at_step=2)


def test_campaign_memory_is_role_isolated() -> None:
    store = CampaignMemoryStore()
    store.add(
        MemoryFact(
            role="attacker",
            visible_at_step=2,
            source_event_ids=["evt_000010"],
            summary="Attacker saw local discovery.",
            action="discover_local",
        )
    )
    store.add(
        MemoryFact(
            role="defender",
            visible_at_step=2,
            source_event_ids=["evt_000020"],
            summary="Defender queried endpoint telemetry.",
            action="query_endpoint",
        )
    )
    defender_memory = store.observation_memory("defender", step=2)
    attacker_memory = store.observation_memory("attacker", step=2)
    assert json.dumps(defender_memory) != json.dumps(attacker_memory)
    assert "Attacker" not in json.dumps(defender_memory)
    assert "Defender" not in json.dumps(attacker_memory)


def test_agents_sdk_session_compaction_uses_sdk_session_primitives(tmp_path: Path) -> None:
    client = AgentsSdkCompatClient(
        role="attacker",
        base_url="http://127.0.0.1:9/v1",
        api_key="EMPTY",
        model="test-model",
        session_id="attacker-session",
        session_db_path=tmp_path / "sessions.sqlite",
        campaign_id="test-campaign",
        session_item_limit=None,
        session_context_limit_tokens=1000,
        session_compaction_ratio=0.15,
        session_hard_stop_ratio=0.95,
        session_compaction_keep_recent_items=2,
    )

    async def seed_and_compact() -> tuple[dict, dict | None, list[dict]]:
        for idx in range(8):
            await client._session.add_items(
                [
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "role": "attacker",
                                "observation_event_ids": [f"evt_{idx:06d}"],
                                "allowed_actions": ["scan_network"],
                            },
                            sort_keys=True,
                        ),
                    },
                    {
                        "role": "assistant",
                        "content": json.dumps(
                            {
                                "action": "scan_network",
                                "intent": f"continue discovery step {idx}",
                                "evidence_ids": [f"evt_{idx:06d}"],
                            },
                            sort_keys=True,
                        ),
                    },
                ]
            )
        before, record = await client._compact_session_if_needed()
        return before, record, await client._session.get_items(limit=None)

    before, record, items = asyncio.run(seed_and_compact())

    assert before["item_count"] == 16
    assert record is not None
    assert record["mode"] == "sdk_session_evidence_preserving_summary"
    assert record["compacted_item_count"] > 0
    assert len(items) < before["item_count"]
    assert "badlands_sdk_session_compaction" in json.dumps(items)
    assert "evt_000000" in record["summary"]


def test_campaign_memory_compaction_preserves_sources_and_recent_facts() -> None:
    store = CampaignMemoryStore()
    for idx in range(6):
        store.add(
            MemoryFact(
                role="defender",
                visible_at_step=2,
                source_event_ids=[f"evt_00010{idx}"],
                summary=f"Visible defender decision {idx} gathered endpoint evidence for host ws-{idx}.",
                action="query_endpoint",
                decision_event_id=f"evt_00020{idx}",
                source_trace_path=f"runs/prior-{idx}.jsonl",
            )
        )
    thresholds = CompactionThresholds(warning_ratio=0.20, compaction_ratio=0.30, hard_stop_ratio=0.99)
    before, after, record = compact_role_campaign_memory(
        store,
        "defender",
        step=2,
        context_limit=700,
        thresholds=thresholds,
        preserve_head=1,
        preserve_recent=2,
    )

    assert record is not None
    assert before.pressure >= thresholds.compaction_ratio
    assert after.token_estimate < before.token_estimate
    assert record.compacted_fact_count == 3
    assert record.source_event_ids == ["evt_000101", "evt_000102", "evt_000103"]
    visible = store.observation_memory("defender", step=2)["facts"]
    assert visible[0]["summary"] == "Visible defender decision 0 gathered endpoint evidence for host ws-0."
    assert visible[-1]["summary"] == "Visible defender decision 5 gathered endpoint evidence for host ws-5."
    compacted = [fact for fact in visible if fact["compacted"]]
    assert len(compacted) == 1
    assert compacted[0]["source_event_ids"] == record.source_event_ids


def test_campaign_compaction_emits_trace_state_transition(tmp_path: Path) -> None:
    env = MissionDeskEnv(tmp_path / "trace.jsonl", seed=7)
    store = CampaignMemoryStore()
    for idx in range(5):
        store.add(
            MemoryFact(
                role="attacker",
                visible_at_step=2,
                source_event_ids=[f"evt_00030{idx}"],
                summary=f"Visible attacker decision {idx} found a role-valid network artifact.",
                action="scan_network",
                decision_event_id=f"evt_00040{idx}",
            )
        )
    compactions = []
    _compact_if_needed(
        env,
        store,
        "attacker",
        2,
        context_limit=600,
        thresholds=CompactionThresholds(warning_ratio=0.20, compaction_ratio=0.30, hard_stop_ratio=0.99),
        compactions=compactions,
        preserve_head=1,
        preserve_recent=1,
    )

    trace = load_trace(tmp_path / "trace.jsonl")
    events = [event for event in trace if event["payload"].get("kind") == "campaign_memory_compacted"]
    assert len(events) == 1
    assert events[0]["parents"] == []
    assert compactions[0].trace_event_id == events[0]["event_id"]
    assert events[0]["payload"]["upstream_source_event_ids"] == compactions[0].source_event_ids


def test_forbidden_memory_text_is_rejected() -> None:
    with pytest.raises(ValueError, match="forbidden memory text"):
        assert_no_forbidden_memory({"summary": "This says host_compromised directly."})


@pytest.mark.parametrize("term", ["sdk_session_db", "cache_path", "hidden_label", "cross_role"])
def test_compaction_forbidden_terms_are_rejected(term: str) -> None:
    with pytest.raises(ValueError):
        assert_no_forbidden_memory({"summary": f"do not carry {term} forward"})


def test_role_visible_cache_named_artifact_is_not_rejected() -> None:
    assert_no_forbidden_memory({"summary": "Analyst reviewed mission-cache-refresh process telemetry."})
