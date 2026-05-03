from __future__ import annotations

import argparse
import json
from pathlib import Path

from badlands.campaigns.continuous import DEFAULT_ENDPOINTS, DEFAULT_MODELS, _context_blocker, run_campaign


def _args(out: Path) -> argparse.Namespace:
    values = {
        "duration_minutes": 0,
        "episode_until": 20,
        "seed_start": 7000,
        "out": out,
        "scenario": None,
        "service_url": None,
        "chat_timeout": 30,
        "sdk_mode": "adapter",
        "memory_mode": "campaign",
        "served_context_target": 262144,
        "context_warning_ratio": 0.70,
        "context_compaction_ratio": 0.85,
        "context_hard_stop_ratio": 0.95,
        "compaction_preserve_head": 1,
        "compaction_preserve_recent": 2,
        "sdk_session_item_limit": 12,
        "health_check_episodes": 1,
        "min_episodes": 1,
        "max_episodes": 1,
        "invalid_spike_threshold": 0.50,
        "run_tier": "262k-campaign-memory-6h",
        "capability_group_id": "badlands-262k-campaign-memory",
        "quiet": True,
    }
    for role, endpoint in DEFAULT_ENDPOINTS.items():
        values[f"{role}_base_url"] = endpoint
        values[f"{role}_api_key"] = "EMPTY"
        values[f"{role}_model"] = DEFAULT_MODELS[role]
    return argparse.Namespace(**values)


def test_adapter_continuous_campaign_writes_operator_artifacts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report = run_campaign(_args(tmp_path / "run"))

    assert report["status"] == "completed"
    assert report["episode_count"] == 1
    assert report["curves"]["risk_vs_elapsed_wall_clock"]
    assert report["role_isolation"]["shared_defender_green_endpoint"] is True
    assert report["role_isolation"]["separate_sdk_sessions"] is True
    assert report["tokens"]["total"] > 0

    state = json.loads((tmp_path / "run" / "operator-state.json").read_text())
    assert state["role_isolation"]["separate_campaign_memory"] is True
    assert state["role_isolation"]["separate_token_accounting"] is True
    assert state["replay"]["ok"] is True
    assert Path(state["paths"]["agents_sdk_sessions"]).name == "agents-sdk-sessions.sqlite"
    assert (tmp_path / "run" / "operator-events.jsonl").read_text()
    assert (tmp_path / "run" / "endpoint-metrics.jsonl").read_text()
    assert (tmp_path / "runs" / "run-ledger.jsonl").read_text()


def test_context_target_blocker_reports_all_roles_below_target() -> None:
    results = [
        {"role": "green", "served_context_tokens": 32768},
        {"role": "attacker", "served_context_tokens": 32768},
        {"role": "defender", "served_context_tokens": 131072},
    ]
    blocker = _context_blocker(results, 262144)
    assert blocker is not None
    assert [item["role"] for item in blocker["roles"]] == ["green", "attacker", "defender"]
