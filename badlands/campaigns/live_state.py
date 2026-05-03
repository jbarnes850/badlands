from __future__ import annotations

import argparse
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from badlands.live_validate import ROLE_ORDER


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Write a dashboard-friendly live state file for an active Badlands campaign.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  badlands-campaign-live-state --run-dir runs/my-campaign
  badlands-campaign-live-state --run-dir runs/my-campaign --interval-seconds 1
  badlands-campaign-live-state --run-dir runs/my-campaign --once --out runs/my-campaign/operator-live-state.json
""",
    )
    parser.add_argument("--run-dir", type=Path, required=True, help="Campaign run directory under runs/.")
    parser.add_argument(
        "--out",
        type=Path,
        help="Output state path. Defaults to <run-dir>/operator-live-state.json.",
    )
    parser.add_argument(
        "--interval-seconds",
        type=float,
        default=0.25,
        help="Polling interval for continuous mode. Default: 0.25.",
    )
    parser.add_argument("--once", action="store_true", help="Write one state snapshot and exit.")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-write status output.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.interval_seconds <= 0:
        raise SystemExit("Error: --interval-seconds must be > 0\nExample: badlands-campaign-live-state --run-dir runs/my-campaign --interval-seconds 0.25")
    run_dir = args.run_dir
    if not run_dir.exists():
        raise SystemExit(f"Error: run directory does not exist: {run_dir}\nExample: badlands-campaign-live-state --run-dir runs/my-campaign")
    out = args.out or run_dir / "operator-live-state.json"
    while True:
        state = build_live_state(run_dir)
        _write_json_atomic(out, state)
        if not args.quiet:
            print(
                "wrote "
                f"{out} episode={state.get('episode')} tokens={state.get('tokens', {}).get('total', 0)} "
                f"live_partial={state.get('live_partial')}"
            )
        if args.once:
            return
        time.sleep(args.interval_seconds)


def build_live_state(run_dir: Path) -> dict[str, Any]:
    base = _load_json(run_dir / "operator-state.json") or {}
    report = _load_json(run_dir / "campaign-report.json") or {}
    tokens, invalid, repairs, actions, latest_trace, current_episode, mission_clock = _parse_traces(run_dir)
    in_flight = _in_flight_actions(run_dir)
    for action in in_flight:
        role = action.get("role")
        if role in tokens:
            tokens[role] += int(action.get("prompt_tokens") or 0) + int(action.get("completion_tokens") or 0)
    tokens["total"] = sum(tokens[role] for role in ROLE_ORDER)
    started = _started_at(run_dir)
    elapsed = max(0.0, time.time() - started)
    now = time.time()
    base.update(
        {
            "status": report.get("status", base.get("status", "running")),
            "episode": max(int(base.get("episode") or 0), current_episode),
            "elapsed_seconds": round(elapsed, 3),
            "tokens": tokens,
            "token_rate": {
                "tokens_per_second": round(tokens["total"] / elapsed, 6) if elapsed else 0.0,
                "tokens_per_minute": round(tokens["total"] / (elapsed / 60), 6) if elapsed else 0.0,
            },
            "invalid_decisions": invalid,
            "repair_pressure": repairs,
            "live_partial": True,
            "live_updated_at_epoch": round(now, 3),
            "live_anchor_epoch": now,
            "mission_clock_at_anchor": mission_clock,
            "live_latest_trace": latest_trace,
            "live_recent_actions": (actions + in_flight)[-24:],
            "sdk_session_growth": _session_stats(run_dir),
        }
    )
    paths = dict(base.get("paths") or {})
    paths["operator_live_state"] = str(run_dir / "operator-live-state.json")
    base["paths"] = paths
    return base


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text())
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _parse_traces(
    run_dir: Path,
) -> tuple[dict[str, int], dict[str, int], dict[str, int], list[dict[str, Any]], str | None, int, int]:
    tokens = {role: 0 for role in ROLE_ORDER}
    invalid = {role: 0 for role in ROLE_ORDER}
    repairs = {role: 0 for role in ROLE_ORDER}
    latest_actions: list[dict[str, Any]] = []
    latest_trace: str | None = None
    current_episode = 0
    mission_clock = 0
    for trace_path in sorted(run_dir.glob("episode-*.jsonl")):
        latest_trace = str(trace_path)
        episode = _episode_from_path(trace_path)
        current_episode = max(current_episode, episode)
        for event in _iter_jsonl(trace_path):
            mission_clock = max(mission_clock, int(event.get("timestamp") or 0))
            if event.get("type") not in {"llm_decision", "llm_decision_invalid"}:
                continue
            role = str(event.get("agent") or "")
            if role not in tokens:
                continue
            payload = event.get("payload", {})
            telemetry = payload.get("inference_telemetry", {})
            prompt_tokens = int(telemetry.get("prompt_token_estimate") or 0)
            completion_tokens = int(telemetry.get("completion_tokens") or 0)
            tokens[role] += prompt_tokens + completion_tokens
            repairs[role] += int(telemetry.get("repair_count") or 0)
            if event.get("type") == "llm_decision_invalid":
                invalid[role] += 1
            latest_actions.append(
                {
                    "episode": episode,
                    "event_id": event.get("event_id"),
                    "role": role,
                    "event_type": event.get("type"),
                    "action": payload.get("action") or payload.get("raw_decision", {}).get("action"),
                    "intent": payload.get("intent") or payload.get("raw_decision", {}).get("intent"),
                    "rationale": payload.get("rationale") or payload.get("raw_decision", {}).get("rationale"),
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "latency_s": telemetry.get("wall_latency_s"),
                    "sdk_context": telemetry.get("sdk_session_context_for_model"),
                }
            )
    tokens["total"] = sum(tokens.values())
    return tokens, invalid, repairs, latest_actions[-24:], latest_trace, current_episode, mission_clock


def _in_flight_actions(run_dir: Path) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for path in sorted((run_dir / "in-flight").glob("*.json")):
        item = _load_json(path)
        if not item:
            continue
        role = str(item.get("role") or "")
        if role not in ROLE_ORDER:
            continue
        actions.append(
            {
                "episode": int(item.get("episode") or 0),
                "event_id": item.get("event_id") or f"inflight:{role}:{int(time.time() * 1000)}",
                "role": role,
                "event_type": "llm_decision_inflight",
                "action": item.get("partial_action") or "generating",
                "intent": "model turn in flight",
                "rationale": item.get("partial_rationale") or item.get("partial_content") or "generating",
                "prompt_tokens": int(item.get("prompt_tokens") or 0),
                "completion_tokens": int(item.get("completion_tokens") or 0),
                "latency_s": round(time.time() - float(item.get("started_at_epoch") or time.time()), 6),
                "sdk_context": None,
                "in_flight": True,
                "partial_content": item.get("partial_content") or "",
                "updated_at_epoch": item.get("updated_at_epoch"),
                "endpoint": item.get("endpoint"),
                "model": item.get("model"),
            }
        )
    return actions


def _iter_jsonl(path: Path) -> list[dict[str, Any]]:
    events = []
    try:
        lines = path.read_text().splitlines()
    except Exception:
        return events
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def _episode_from_path(path: Path) -> int:
    try:
        return int(path.stem.split("-")[1])
    except Exception:
        return 0


def _session_stats(run_dir: Path) -> dict[str, dict[str, Any]]:
    db = run_dir / "agents-sdk-sessions.sqlite"
    if not db.exists():
        return {}
    try:
        conn = sqlite3.connect(db)
        rows = conn.execute(
            "SELECT session_id, count(*), sum(length(message_data)) "
            "FROM agent_messages GROUP BY session_id"
        ).fetchall()
    except sqlite3.Error:
        return {}
    out: dict[str, dict[str, Any]] = {}
    for session_id, count, size_bytes in rows:
        role = next((item for item in ROLE_ORDER if f"-{item}-session" in str(session_id)), str(session_id))
        out[role] = {
            "session_id": session_id,
            "items": int(count or 0),
            "bytes": int(size_bytes or 0),
            "token_estimate": _estimate_tokens_from_chars(int(size_bytes or 0)),
        }
    return out


def _started_at(run_dir: Path) -> float:
    for name in ("live-serving-preflight.json", "operator-events.jsonl", "campaign-run.log"):
        path = run_dir / name
        if path.exists():
            return path.stat().st_mtime
    return time.time()


def _estimate_tokens_from_chars(chars: int) -> int:
    return max(1, (chars + 3) // 4)


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True))
    tmp.replace(path)


if __name__ == "__main__":
    main()
