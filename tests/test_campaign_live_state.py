from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from badlands.campaigns.live_state import build_live_state, main


def test_live_state_merges_trace_tokens_and_sdk_session_growth(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "operator-state.json").write_text(
        json.dumps(
            {
                "campaign_id": "run",
                "status": "running",
                "episode": 0,
                "paths": {"operator_state": str(run / "operator-state.json")},
            }
        )
    )
    (run / "campaign-report.json").write_text(json.dumps({"status": "running"}))
    (run / "live-serving-preflight.json").write_text("[]")
    trace = run / "episode-000001.jsonl"
    trace.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "event_id": "evt_1",
                        "type": "llm_decision",
                        "agent": "attacker",
                        "payload": {
                            "action": "scan_network",
                            "intent": "find next target",
                            "inference_telemetry": {
                                "prompt_token_estimate": 100,
                                "completion_tokens": 20,
                                "repair_count": 1,
                                "wall_latency_s": 2.5,
                                "sdk_session_context_for_model": {"item_count": 2, "token_estimate": 80},
                            },
                        },
                    }
                )
            ]
        )
        + "\n"
    )
    db = run / "agents-sdk-sessions.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE agent_messages (session_id TEXT, message_data TEXT)")
    conn.execute(
        "INSERT INTO agent_messages VALUES (?, ?)",
        ("run-attacker-session", json.dumps({"role": "user", "content": "x" * 40})),
    )
    conn.commit()

    state = build_live_state(run)

    assert state["live_partial"] is True
    assert state["episode"] == 1
    assert state["tokens"]["attacker"] == 120
    assert state["tokens"]["total"] == 120
    assert state["repair_pressure"]["attacker"] == 1
    assert state["live_recent_actions"][-1]["action"] == "scan_network"
    assert state["live_recent_actions"][-1]["sdk_context"]["token_estimate"] == 80
    assert state["sdk_session_growth"]["attacker"]["items"] == 1
    assert state["paths"]["operator_live_state"] == str(run / "operator-live-state.json")


def test_live_state_cli_once_writes_output(tmp_path: Path, monkeypatch) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "operator-state.json").write_text(json.dumps({"campaign_id": "run", "paths": {}}))
    out = run / "operator-live-state.json"
    monkeypatch.setattr(
        "sys.argv",
        ["badlands-campaign-live-state", "--run-dir", str(run), "--out", str(out), "--once", "--quiet"],
    )

    main()

    assert json.loads(out.read_text())["live_partial"] is True
