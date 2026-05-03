from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from badlands.agents.decision_quality import decision_quality_report
from badlands.agents.llm import AttackerLLM, DefenderLLM, GreenUserLLM, InvalidLLMDecision, LLMDecision
from badlands.core.attacker_actions import ATTACKER_ACTION_DURATIONS
from badlands.core.defender_actions import DEFENDER_ACTION_DURATIONS
from badlands.core.env import MissionDeskEnv
from badlands.core.observations import attacker_view
from badlands.core.trace import load_trace
from badlands.scoring.replay import derive_scores

ROLE_ORDER = ("green", "attacker", "defender")
ATTACK_DURATIONS = ATTACKER_ACTION_DURATIONS
DEFENDER_DURATIONS = DEFENDER_ACTION_DURATIONS


@dataclass(frozen=True)
class RoleEndpoint:
    role: str
    base_url: str
    api_key: str
    model: str


@dataclass
class LiveActorState:
    role: str
    actor: Any
    next_due: int
    remaining: int
    action_gap: int
    retry_delay: int
    durations: dict[str, int]
    observe: Callable[[], dict[str, Any]]
    apply: Callable[[LLMDecision, str], None]


class EndpointFailure(RuntimeError):
    def __init__(self, role: str, endpoint: str, check: str, detail: str):
        super().__init__(f"{role} endpoint {endpoint} failed {check}: {detail}")
        self.role = role
        self.endpoint = endpoint
        self.check = check
        self.detail = detail


def _http_json(url: str, *, api_key: str = "EMPTY", body: dict[str, Any] | None = None, timeout: int = 30) -> tuple[int, dict[str, Any], float]:
    data = None if body is None else json.dumps(body).encode()
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=headers)
    started = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode() or "{}")
        return int(resp.status), payload, round(time.perf_counter() - started, 6)


def configured_endpoints(args: argparse.Namespace) -> dict[str, RoleEndpoint]:
    def env(role: str, key: str, default: str = "") -> str:
        return getattr(args, f"{role}_{key}") or os.getenv(f"BADLANDS_{role.upper()}_LLM_{key.upper()}", default)

    fallback_base = os.getenv("BADLANDS_LLM_BASE_URL", "")
    fallback_key = os.getenv("BADLANDS_LLM_API_KEY", "EMPTY")
    fallback_model = os.getenv("BADLANDS_LLM_MODEL", "")
    roles: dict[str, RoleEndpoint] = {}
    for role in ROLE_ORDER:
        roles[role] = RoleEndpoint(
            role=role,
            base_url=(env(role, "base_url") or fallback_base).rstrip("/"),
            api_key=env(role, "api_key", fallback_key),
            model=env(role, "model") or fallback_model,
        )
    return roles


def preflight(endpoints: dict[str, RoleEndpoint], *, chat_timeout: int) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for cfg in endpoints.values():
        if not cfg.base_url or not cfg.model:
            raise EndpointFailure(cfg.role, cfg.base_url or "<unset>", "configuration", "base URL and model are required")
        try:
            status, models, latency = _http_json(f"{cfg.base_url}/models", api_key=cfg.api_key, timeout=min(chat_timeout, 30))
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            raise EndpointFailure(cfg.role, cfg.base_url, "/v1/models", str(exc)) from exc
        model_items = [item for item in models.get("data", []) if isinstance(item, dict)]
        model_ids = [str(item.get("id")) for item in model_items]
        if status != 200:
            raise EndpointFailure(cfg.role, cfg.base_url, "/v1/models", f"HTTP {status}")
        if cfg.model not in model_ids:
            raise EndpointFailure(cfg.role, cfg.base_url, "configured model id", f"{cfg.model!r} not in {model_ids!r}")
        configured_model = next(item for item in model_items if str(item.get("id")) == cfg.model)
        max_model_len = configured_model.get("max_model_len")
        chat_body = {
            "model": cfg.model,
            "messages": [
                {"role": "system", "content": "Return JSON only. Do not include reasoning or hidden thinking."},
                {"role": "user", "content": 'Return {"ok": true, "role": "' + cfg.role + '"}.'},
            ],
            "temperature": 0,
            "max_tokens": 256,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "badlands_preflight",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["ok", "role"],
                        "properties": {
                            "ok": {"type": "boolean"},
                            "role": {"type": "string", "enum": [cfg.role]},
                        },
                    },
                },
            },
            "structured_outputs": {
                "json": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["ok", "role"],
                    "properties": {
                        "ok": {"type": "boolean"},
                        "role": {"type": "string", "enum": [cfg.role]},
                    },
                },
                "disable_additional_properties": True,
            },
            "chat_template_kwargs": {"enable_thinking": False},
        }
        try:
            chat_status, chat, chat_latency = _http_json(
                f"{cfg.base_url}/chat/completions",
                api_key=cfg.api_key,
                body=chat_body,
                timeout=chat_timeout,
            )
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            raise EndpointFailure(cfg.role, cfg.base_url, "bounded JSON chat", str(exc)) from exc
        if chat_status != 200:
            raise EndpointFailure(cfg.role, cfg.base_url, "bounded JSON chat", f"HTTP {chat_status}")
        message = chat.get("choices", [{}])[0].get("message", {})
        content = message.get("content")
        reasoning = message.get("reasoning")
        if reasoning not in (None, ""):
            raise EndpointFailure(
                cfg.role,
                cfg.base_url,
                "reasoning disabled canary",
                "chat response included message.reasoning despite enable_thinking=false",
            )
        if not isinstance(content, str) or not content.strip():
            raise EndpointFailure(cfg.role, cfg.base_url, "JSON compatibility", "chat response did not include content")
        try:
            json.loads(content)
        except json.JSONDecodeError as exc:
            raise EndpointFailure(cfg.role, cfg.base_url, "JSON compatibility", str(exc)) from exc
        usage = chat.get("usage", {})
        backpressure = _fetch_backpressure_evidence(cfg)
        results.append(
            {
                "role": cfg.role,
                "endpoint": cfg.base_url,
                "model": cfg.model,
                "models_latency_s": latency,
                "chat_latency_s": chat_latency,
                "ttft_s": None,
                "ttft_status": "unavailable_non_streaming_preflight",
                "prompt_tokens": usage.get("prompt_tokens"),
                "completion_tokens": usage.get("completion_tokens"),
                "available_model_count": len(model_ids),
                "advertised_context_tokens": max_model_len,
                "served_context_tokens": max_model_len,
                "served_context_evidence": "/v1/models max_model_len",
                "backpressure": backpressure,
            }
        )
    return results


def _fetch_backpressure_evidence(cfg: RoleEndpoint) -> dict[str, Any]:
    metrics_url = _metrics_url(cfg.base_url)
    evidence = {
        "metrics_url": metrics_url,
        "status": "unavailable",
        "running": None,
        "waiting": None,
        "kv_cache_usage_perc": None,
        "preemptions_total": None,
        "reason": None,
    }
    try:
        req = urllib.request.Request(metrics_url, headers={"Authorization": f"Bearer {cfg.api_key}"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            raw = resp.read().decode()
    except Exception as exc:
        evidence["reason"] = str(exc)
        return evidence
    evidence.update(_parse_vllm_metrics(raw))
    evidence["status"] = "available"
    evidence["reason"] = None
    return evidence


def _metrics_url(base_url: str) -> str:
    base = base_url.rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]
    return f"{base}/metrics"


def _parse_vllm_metrics(raw: str) -> dict[str, Any]:
    values: dict[str, float] = {}
    for line in raw.splitlines():
        if not line or line.startswith("#"):
            continue
        name, _, value = line.partition(" ")
        metric = name.split("{", 1)[0]
        try:
            values[metric] = float(value)
        except ValueError:
            continue
    return {
        "running": _first_metric(values, ("vllm:num_requests_running", "vllm_num_requests_running")),
        "waiting": _first_metric(values, ("vllm:num_requests_waiting", "vllm_num_requests_waiting")),
        "kv_cache_usage_perc": _first_metric(values, ("vllm:gpu_cache_usage_perc", "vllm_gpu_cache_usage_perc")),
        "preemptions_total": _first_metric(values, ("vllm:num_preemptions_total", "vllm_num_preemptions_total")),
    }


def _first_metric(values: dict[str, float], names: tuple[str, ...]) -> float | None:
    for name in names:
        if name in values:
            return values[name]
    return None


def _log(args: argparse.Namespace, message: str) -> None:
    if not getattr(args, "quiet", False):
        print(message, flush=True)


def prepare_live_schedule(env: MissionDeskEnv) -> None:
    env.queue.clear()
    env._schedule_benign_noise()


async def run_live_episode(args: argparse.Namespace) -> dict[str, Any]:
    _log(args, f"[live] starting bounded episode seed={args.seed} until={args.until} trace={args.trace}")
    env = MissionDeskEnv(
        args.trace,
        seed=args.seed,
        service_url=args.service_url,
        scenario=args.scenario,
    )
    prepare_live_schedule(env)
    states = _live_actor_states(env, args)
    invalid_counts = {role: 0 for role in ROLE_ORDER}
    start = time.perf_counter()
    while any(state.remaining > 0 for state in states.values()):
        due_time = min((state.next_due for state in states.values() if state.remaining > 0), default=args.until + 1)
        if due_time > args.until:
            break
        env.run(due_time)
        for state in states.values():
            state.next_due = max(state.next_due, env.now)
        due = [states[role] for role in ROLE_ORDER if states[role].remaining > 0 and states[role].next_due <= env.now]
        _log(args, f"[live] t={env.now} due_roles={','.join(state.role for state in due)}")
        snapshots = [(state, state.observe()) for state in due]
        proposals = await asyncio.gather(
            *[asyncio.to_thread(_decide, state, observation) for state, observation in snapshots],
            return_exceptions=True,
        )
        for (state, observation), proposal in _ordered_proposals(snapshots, proposals):
            state.remaining -= 1
            if isinstance(proposal, InvalidLLMDecision):
                invalid_counts[state.role] += 1
                _emit_invalid(env, state.role, proposal, observation)
                _log(args, _format_live_decision_log("invalid", state.role, proposal.telemetry, reason=proposal.reason))
                state.next_due = env.now + state.retry_delay
                continue
            if isinstance(proposal, Exception):
                invalid = InvalidLLMDecision(state.role, {}, str(proposal))
                invalid_counts[state.role] += 1
                _emit_invalid(env, state.role, invalid, observation)
                _log(args, _format_live_decision_log("invalid", state.role, {}, reason=str(proposal)))
                state.next_due = env.now + state.retry_delay
                continue
            decision_event_id = _emit_valid(env, state.role, observation, proposal)
            _log(
                args,
                _format_live_decision_log(
                    "valid",
                    state.role,
                    proposal.inference_telemetry,
                    action=proposal.action,
                    event_id=decision_event_id,
                ),
            )
            state.apply(proposal, decision_event_id)
            _log(args, f"[live] t={env.now} apply role={state.role} action={proposal.action} decision_event={decision_event_id}")
            state.next_due = env.now + state.durations[proposal.action] + state.action_gap
    score = env.run(args.until)
    _log(args, f"[live] completed score_snapshot trace={args.trace} score={json.dumps(score, sort_keys=True)}")
    return {
        "score": score,
        "episode_wall_clock_s": round(time.perf_counter() - start, 6),
        "invalid_counts": invalid_counts,
        "role_isolation_evidence": _actor_isolation_evidence(states),
    }


def _live_actor_states(env: MissionDeskEnv, args: argparse.Namespace) -> dict[str, LiveActorState]:
    green = GreenUserLLM(cache_dir=args.cache, seed=args.seed)
    attacker = AttackerLLM(cache_dir=args.cache, seed=args.seed)
    defender = DefenderLLM(cache_dir=args.cache, seed=args.seed)
    green_i = {"value": 0}

    def green_observation() -> dict[str, Any]:
        i = green_i["value"]
        task = env._green_workflow_task(i, {})
        required_role = str(task.get("required_role", "mission_analyst"))
        users = [user_id for user_id, user in env.state.users.items() if user.role == required_role] or list(env.state.users)
        user = users[i % len(users)]
        host = env.state.users[user].host_id
        return {
            "user": {"user_id": user, "host_id": host, "role": env.state.users[user].role},
            "workflow": {
                "task_id": task["task_id"],
                "workflow_id": task.get("workflow_id"),
                "task_type": task.get("task_type"),
                "deadline_at": task.get("deadline_at"),
                "priority": task.get("priority"),
                "history": env.state.tickets[-5:],
                "mission_completed": env.state.mission_completed,
                "mission_failed": env.state.mission_failed,
            },
            "mission": [env._public_task_context(task)],
        }

    def apply_green(decision: LLMDecision, decision_event_id: str) -> None:
        i = green_i["value"]
        green_i["value"] += 1
        env.green_task(
            i,
            selected_action=decision.action,
            selected_parameters=decision.parameters,
            decision_event_id=decision_event_id,
        )

    return {
        "green": LiveActorState("green", green, 0, args.green_decisions, 4, 2, {"use_mission_app": 2, "read_write_file": 2, "create_ticket": 1}, green_observation, apply_green),
        "attacker": LiveActorState("attacker", attacker, 0, args.attacker_decisions, 1, 2, ATTACK_DURATIONS, lambda: attacker_view(env.trace.events), lambda decision, eid: env.attacker(decision.action, decision.parameters, decision_event_id=eid)),
        "defender": LiveActorState("defender", defender, args.defender_first_delay, args.defender_decisions, 5, 5, DEFENDER_DURATIONS, env.defender_observation, lambda decision, eid: env.defender(decision.action, decision.parameters, decision_event_id=eid)),
    }


def _decide(state: LiveActorState, observation: dict[str, Any]) -> LLMDecision:
    return state.actor.decide(observation)


def _ordered_proposals(
    snapshots: list[tuple[LiveActorState, dict[str, Any]]],
    proposals: list[LLMDecision | BaseException],
) -> list[tuple[tuple[LiveActorState, dict[str, Any]], LLMDecision | BaseException]]:
    return sorted(zip(snapshots, proposals, strict=True), key=lambda item: ROLE_ORDER.index(item[0][0].role))


def _actor_isolation_evidence(states: dict[str, LiveActorState]) -> dict[str, Any]:
    return {
        "actor_classes": {role: state.actor.__class__.__name__ for role, state in states.items()},
        "actor_instance_ids": {role: id(state.actor) for role, state in states.items()},
        "role_prompt_contracts": {role: state.actor.role for role, state in states.items()},
    }


def _emit_valid(env: MissionDeskEnv, role: str, observation: dict[str, Any], decision: LLMDecision) -> str:
    return env.trace.emit("llm_decision", env.now, decision.trace_payload(role, observation), agent=role, parents=decision.evidence_ids)


def _emit_invalid(env: MissionDeskEnv, role: str, exc: InvalidLLMDecision, observation: dict[str, Any]) -> None:
    env.trace.emit(
        "llm_decision_invalid",
        env.now,
        {"role": role, "raw_decision": exc.raw, "reason": exc.reason, "observation": observation, "inference_telemetry": exc.telemetry},
        agent=role,
    )


def build_report(
    *,
    args: argparse.Namespace,
    endpoints: dict[str, RoleEndpoint],
    preflight_results: list[dict[str, Any]],
    episode: dict[str, Any],
    replay_score: dict[str, Any],
) -> dict[str, Any]:
    events = load_trace(args.trace)
    score_snapshots = [event for event in events if event["type"] == "score_snapshot"]
    if not score_snapshots:
        raise RuntimeError(f"completed-run blocker: score_snapshot missing in trace {args.trace}")
    decisions = [event for event in events if event["type"] in {"llm_decision", "llm_decision_invalid"}]
    telemetry = [_decision_telemetry(event) for event in decisions]
    role_isolation = _role_isolation(endpoints, args.cache, events, episode.get("role_isolation_evidence", {}))
    summary = _telemetry_summary(telemetry)
    replay_ok = replay_score == {k: v for k, v in score_snapshots[-1]["payload"].items() if k != "evidence"}
    report = {
        "status": "completed",
        "failure_classification": _failure_classification(preflight_results, telemetry, events),
        "serving_backpressure": _serving_backpressure_summary(preflight_results),
        "trace_path": str(args.trace),
        "cache_path": str(args.cache),
        "report_path": str(args.report),
        "seed": args.seed,
        "until": args.until,
        "wall_clock_s": episode["episode_wall_clock_s"],
        "preflight": preflight_results,
        "role_isolation": role_isolation,
        "deterministic_fan_in": {
            "enabled": True,
            "observation_snapshot_before_fanout": True,
            "fan_in_order": list(ROLE_ORDER),
            "canonical_replay_source": "Badlands JSONL trace",
        },
        "telemetry": summary,
        "invalid_decision_rate": summary["invalid_decision_rate"],
        "repair_count": summary["repair_count"],
        "replay": {"ok": replay_ok, "score": replay_score},
        "score_summary": score_snapshots[-1]["payload"],
        "qualitative_output_checklist": _qualitative_outputs(events),
        "decision_quality": decision_quality_report(events),
        "ds29_handoff": {
            "consume_fields": [
                "role",
                "endpoint",
                "model",
                "cache_key",
                "cache_hit",
                "prompt_token_estimate",
                "completion_tokens",
                "wall_latency_s",
                "attempt_count",
                "repair_count",
                "validation_error",
                "invalid_decision_reason",
                "sdk_run_id",
                "sdk_session_id",
                "badlands_event_id",
                "trace_path",
            ],
            "boundary": "DS-24 emits telemetry, role isolation metadata, deterministic fan-in contract, and passive correlation IDs only. DS-29 owns durable actor memory, campaign compaction, multi-episode state, and SDK sessions.",
        },
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True))
    return report


def _decision_telemetry(event: dict[str, Any]) -> dict[str, Any]:
    telemetry = event["payload"].get("inference_telemetry", {})
    return {"badlands_event_id": event["event_id"], "event_type": event["type"], "role": event.get("agent"), **telemetry}


def _telemetry_summary(telemetry: list[dict[str, Any]]) -> dict[str, Any]:
    valid = [item for item in telemetry if item["event_type"] == "llm_decision"]
    invalid = [item for item in telemetry if item["event_type"] == "llm_decision_invalid"]
    completion_tokens = sum(int(item.get("completion_tokens") or 0) for item in telemetry)
    wall = sum(float(item.get("wall_latency_s") or 0.0) for item in telemetry)
    by_role = {}
    for role in ROLE_ORDER:
        role_items = [item for item in telemetry if item.get("role") == role]
        latencies = sorted(float(item.get("wall_latency_s") or 0.0) for item in role_items)
        by_role[role] = {
            "decisions": len(role_items),
            "invalid_decisions": sum(1 for item in role_items if item["event_type"] == "llm_decision_invalid"),
            "latency_p50_s": _percentile(latencies, 50),
            "latency_p95_s": _percentile(latencies, 95),
            "completion_tokens": sum(int(item.get("completion_tokens") or 0) for item in role_items),
        }
    return {
        "decisions": len(telemetry),
        "valid_decisions": len(valid),
        "invalid_decisions": len(invalid),
        "invalid_decision_rate": round(len(invalid) / len(telemetry), 6) if telemetry else 0.0,
        "repair_count": sum(int(item.get("repair_count") or 0) for item in telemetry),
        "initial_invalid_count": sum(int(item.get("initial_invalid_count") or 0) for item in telemetry),
        "repairs_attempted": sum(int(item.get("repairs_attempted") or 0) for item in telemetry),
        "repair_invalid_count": sum(int(item.get("repair_invalid_count") or 0) for item in telemetry),
        "final_invalid_count": sum(int(item.get("final_invalid_count") or 0) for item in telemetry),
        "parse_failures": sum(int(item.get("parse_failures") or 0) for item in telemetry),
        "completion_tokens": completion_tokens,
        "inference_wall_latency_s": round(wall, 6),
        "output_tokens_per_s": round(completion_tokens / wall, 6) if wall > 0 else 0.0,
        "per_role": by_role,
    }


def _percentile(values: list[float], pct: int) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return round(values[0], 6)
    return round(statistics.quantiles(values, n=100, method="inclusive")[pct - 1], 6)


def _role_isolation(
    endpoints: dict[str, RoleEndpoint],
    cache: Path,
    events: list[dict[str, Any]],
    actor_evidence: dict[str, Any],
) -> dict[str, Any]:
    shared = {}
    for role in ROLE_ORDER:
        shared[role] = [other for other in ROLE_ORDER if other != role and endpoints[other].base_url == endpoints[role].base_url]
    decisions = [event for event in events if event["type"] in {"llm_decision", "llm_decision_invalid"}]
    cache_paths_by_role = {
        role: sorted(
            {
                str(event["payload"].get("inference_telemetry", {}).get("cache_path"))
                for event in decisions
                if event.get("agent") == role and event["payload"].get("inference_telemetry", {}).get("cache_path")
            }
        )
        for role in ROLE_ORDER
    }
    observation_keys_by_role = {
        role: sorted(
            {
                key
                for event in decisions
                if event.get("agent") == role
                for key in event["payload"].get("observation", {}).keys()
            }
        )
        for role in ROLE_ORDER
    }
    cache_key_ok = {
        role: all(Path(path).name.startswith(f"{role}_") for path in paths)
        for role, paths in cache_paths_by_role.items()
    }
    actor_ids = actor_evidence.get("actor_instance_ids", {})
    return {
        "shared_endpoint_infrastructure": {role: peers for role, peers in shared.items() if peers},
        "separate_actor_instances": {
            "ok": len(set(actor_ids.values())) == len(ROLE_ORDER) if actor_ids else None,
            "evidence": actor_ids,
        },
        "separate_role_prompts": {
            "ok": set(actor_evidence.get("role_prompt_contracts", {})) == set(ROLE_ORDER) if actor_evidence else None,
            "evidence": actor_evidence.get("role_prompt_contracts", {}),
        },
        "separate_observation_surfaces": {
            "ok": len({tuple(keys) for keys in observation_keys_by_role.values() if keys}) > 1,
            "evidence": observation_keys_by_role,
        },
        "role_scoped_cache_keys": {
            "ok": all(cache_key_ok.values()),
            "evidence": cache_paths_by_role,
        },
        "cache_path": str(cache),
    }


def _qualitative_outputs(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {role: [] for role in ROLE_ORDER}
    for event in events:
        if event["type"] not in {"llm_decision", "llm_decision_invalid"}:
            continue
        role = event["agent"]
        raw = event["payload"].get("raw_decision", {})
        telemetry = event["payload"].get("inference_telemetry", {})
        out[role].append(
            {
                "event_id": event["event_id"],
                "event_type": event["type"],
                "timestamp": event["timestamp"],
                "action": raw.get("action"),
                "intent": raw.get("intent"),
                "rationale": raw.get("rationale"),
                "expected_effect": raw.get("expected_effect"),
                "risk": raw.get("risk"),
                "invalid_reason": event["payload"].get("reason"),
                "raw_outputs": raw.get("raw_outputs") or telemetry.get("raw_outputs", []),
            }
        )
    return out


def _failure_classification(preflight_results: list[dict[str, Any]], telemetry: list[dict[str, Any]], events: list[dict[str, Any]]) -> dict[str, Any]:
    invalid_rate = sum(1 for item in telemetry if item["event_type"] == "llm_decision_invalid") / len(telemetry) if telemetry else 0
    preflight_max = max((float(item["chat_latency_s"]) for item in preflight_results), default=0.0)
    return {
        "endpoint_failure": False,
        "serving_bottleneck": _serving_bottleneck_status(preflight_results, preflight_max),
        "agent_loop_bottleneck": invalid_rate > 0.2 or sum(int(item.get("repair_count") or 0) for item in telemetry) > 0,
        "environment_failure": not any(event["type"] == "score_snapshot" for event in events),
    }


def _serving_bottleneck_status(preflight_results: list[dict[str, Any]], preflight_max: float) -> str | bool:
    if preflight_max > 60:
        return True
    available = [item.get("backpressure", {}) for item in preflight_results if item.get("backpressure", {}).get("status") == "available"]
    if not available:
        return "unknown"
    if any((item.get("waiting") or 0) > 0 or (item.get("preemptions_total") or 0) > 0 for item in available):
        return True
    return False


def _serving_backpressure_summary(preflight_results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "status": _serving_bottleneck_status(
            preflight_results,
            max((float(item["chat_latency_s"]) for item in preflight_results), default=0.0),
        ),
        "evidence": [
            {
                "role": item["role"],
                "endpoint": item["endpoint"],
                "ttft_s": item.get("ttft_s"),
                "ttft_status": item.get("ttft_status"),
                "backpressure": item.get("backpressure"),
            }
            for item in preflight_results
        ],
    }


def _format_live_decision_log(
    status: str,
    role: str,
    telemetry: dict[str, Any],
    *,
    action: str | None = None,
    event_id: str | None = None,
    reason: str | None = None,
) -> str:
    parts = [
        f"[llm] status={status}",
        f"role={role}",
        f"action={action or '-'}",
        f"event={event_id or '-'}",
        f"endpoint={telemetry.get('endpoint', '-')}",
        f"model={telemetry.get('model', '-')}",
        f"cache={'hit' if telemetry.get('cache_hit') else 'miss'}",
        f"attempts={telemetry.get('attempt_count', 0)}",
        f"repairs={telemetry.get('repair_count', 0)}",
        f"out_tokens={telemetry.get('completion_tokens', 0)}",
        f"latency_s={telemetry.get('wall_latency_s', 0)}",
    ]
    if reason:
        parts.append(f"reason={reason}")
    return " ".join(parts)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--until", type=int, default=40)
    parser.add_argument("--trace", type=Path, default=Path("runs/live-validation.jsonl"))
    parser.add_argument("--cache", type=Path, default=Path("runs/live-validation-cache"))
    parser.add_argument("--report", type=Path, default=Path("runs/live-validation-report.json"))
    parser.add_argument("--scenario", type=Path)
    parser.add_argument("--service-url")
    parser.add_argument("--chat-timeout", type=int, default=int(os.getenv("BADLANDS_LLM_TIMEOUT_SECONDS", "240")))
    parser.add_argument("--attacker-decisions", type=int, default=4)
    parser.add_argument("--defender-decisions", type=int, default=3)
    parser.add_argument("--green-decisions", type=int, default=3)
    parser.add_argument("--defender-first-delay", type=int, default=10)
    parser.add_argument("--quiet", action="store_true")
    for role in ROLE_ORDER:
        parser.add_argument(f"--{role}-base-url")
        parser.add_argument(f"--{role}-api-key")
        parser.add_argument(f"--{role}-model")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    endpoints = configured_endpoints(args)
    try:
        _log(args, "[preflight] checking /v1/models, configured IDs, and bounded JSON chat")
        preflight_results = preflight(endpoints, chat_timeout=args.chat_timeout)
        for item in preflight_results:
            _log(
                args,
                "[preflight] "
                f"role={item['role']} endpoint={item['endpoint']} model={item['model']} "
                f"models_latency_s={item['models_latency_s']} chat_latency_s={item['chat_latency_s']} "
                f"completion_tokens={item['completion_tokens']}",
            )
        episode = asyncio.run(run_live_episode(args))
        _log(args, f"[replay] replaying trace={args.trace}")
        replay_score = derive_scores(load_trace(args.trace))
        report = build_report(
            args=args,
            endpoints=endpoints,
            preflight_results=preflight_results,
            episode=episode,
            replay_score=replay_score,
        )
        _log(args, f"[report] wrote {args.report}")
    except EndpointFailure as exc:
        payload = _endpoint_failure_payload(exc)
        _write_report(args.report, payload)
        raise SystemExit(json.dumps(payload, indent=2, sort_keys=True))
    except Exception as exc:
        payload = {
            "status": "failed",
            "failure_classification": {
                "endpoint_failure": False,
                "serving_bottleneck": False,
                "agent_loop_bottleneck": False,
                "environment_failure": True,
            },
            "blocker": str(exc),
            "trace_path": str(args.trace),
        }
        _write_report(args.report, payload)
        raise SystemExit(json.dumps(payload, indent=2, sort_keys=True))
    print(json.dumps(report, indent=2, sort_keys=True))


def _endpoint_failure_payload(exc: EndpointFailure) -> dict[str, Any]:
    return {
        "status": "failed",
        "failure_classification": {
            "endpoint_failure": True,
            "serving_bottleneck": False,
            "agent_loop_bottleneck": False,
            "environment_failure": False,
        },
        "blocker": str(exc),
        "role": exc.role,
        "endpoint": exc.endpoint,
        "check": exc.check,
        "detail": exc.detail,
    }


def _write_report(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
