from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from badlands.agents.campaign_memory import CampaignMemoryStore, MemoryFact, assert_no_forbidden_memory, memory_fact_from_decision
from badlands.campaigns.agents_sdk_smoke import run_campaign
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


def test_forbidden_memory_text_is_rejected() -> None:
    with pytest.raises(ValueError, match="forbidden memory text"):
        assert_no_forbidden_memory({"summary": "This says host_compromised directly."})
