from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

from badlands.agents.agents_sdk import AgentsSdkCompatClient
from badlands.agents.campaign_memory import CampaignMemoryStore, add_campaign_memory, memory_fact_from_decision
from badlands.agents.decision_quality import decision_quality_report
from badlands.agents.llm import AttackerLLM, DefenderLLM, GreenUserLLM, InvalidLLMDecision, LLMDecision
from badlands.core.attacker_actions import ATTACKER_ACTION_DURATIONS
from badlands.core.defender_actions import DEFENDER_ACTION_DURATIONS
from badlands.core.env import MissionDeskEnv
from badlands.core.observations import attacker_view
from badlands.core.trace import load_trace
from badlands.live_validate import ROLE_ORDER, RoleEndpoint, configured_endpoints, preflight, prepare_live_schedule
from badlands.scoring.replay import derive_scores

HARNESS_VERSION = "agents-sdk-campaign-v1"


class DeterministicCampaignClient:
    def __init__(self, *, role: str, session_id: str, campaign_id: str):
        self.role = role
        self.model = "deterministic-adapter"
        self.base_url = "adapter://deterministic"
        self.session_id = session_id
        self.campaign_id = campaign_id
        self.calls = 0
        self.last_completion_telemetry: dict[str, Any] = {}

    def complete_json(self, messages: list[dict[str, str]], **_: Any) -> dict[str, Any]:
        self.calls += 1
        prompt = messages[-1]["content"]
        observation = json.loads(prompt)["observation"]
        memory_ids = observation.get("campaign_memory", {}).get("source_event_ids", [])
        allowed_ids = json.loads(prompt).get("observation_event_ids", [])
        evidence_ids = memory_ids[:1] or allowed_ids[:1]
        decision = self._decision(observation, evidence_ids)
        self.last_completion_telemetry = {
            "endpoint": self.base_url,
            "model": self.model,
            "sdk_mode": "adapter_fallback",
            "sdk_run_id": f"{self.campaign_id}-{self.role}-fallback-{self.calls}",
            "sdk_session_id": self.session_id,
            "fallback_session_id": self.session_id,
            "fallback_decision_id": f"{self.role}-{self.calls}",
            "attempt_count": 1,
            "repair_count": 0,
            "prompt_token_estimate": max(1, len(prompt) // 4),
            "completion_tokens": max(1, len(json.dumps(decision)) // 4),
            "wall_latency_s": 0.0,
            "validation_error": None,
            "invalid_decision_reason": None,
            "raw_outputs": [{"attempt": 1, "content": json.dumps(decision, sort_keys=True)}],
            "initial_invalid_count": 0,
            "repairs_attempted": 0,
            "repair_invalid_count": 0,
            "final_invalid_count": 0,
            "parse_failures": 0,
        }
        return decision

    def _decision(self, observation: dict[str, Any], evidence_ids: list[str]) -> dict[str, Any]:
        has_memory = bool(observation.get("campaign_memory", {}).get("facts"))
        if self.role == "attacker":
            action = "scan_network" if has_memory else "discover_local"
            intent = "Use prior visible discovery to move from local discovery into network scanning." if has_memory else "Establish local foothold context."
            expected_effect = "Reveal reachable network hosts." if has_memory else "Reveal local host and user context."
        elif self.role == "defender":
            action = "query_identity" if has_memory else "query_endpoint"
            intent = "Use remembered endpoint uncertainty to check identity activity." if has_memory else "Gather endpoint evidence before disruptive action."
            expected_effect = "Collect identity evidence." if has_memory else "Collect endpoint telemetry."
        else:
            action = "use_mission_app"
            intent = "Continue the mission workflow using remembered user-visible task context." if has_memory else "Attempt assigned mission work."
            expected_effect = "Progress the mission task."
        return {
            "intent": intent,
            "action": action,
            "parameters": {},
            "confidence": 0.72,
            "evidence_ids": evidence_ids,
            "rationale": intent,
            "expected_effect": expected_effect,
            "risk": "The observation may not provide enough context for a stronger action.",
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--steps", type=int, default=2)
    parser.add_argument("--until", type=int, default=40)
    parser.add_argument("--out", type=Path, default=Path("runs/agents-sdk-campaign-smoke"))
    parser.add_argument("--scenario", type=Path)
    parser.add_argument("--service-url")
    parser.add_argument("--chat-timeout", type=int, default=int(os.getenv("BADLANDS_LLM_TIMEOUT_SECONDS", "240")))
    parser.add_argument("--sdk-mode", choices=("direct", "adapter"), default="direct")
    parser.add_argument("--quiet", action="store_true")
    for role in ROLE_ORDER:
        parser.add_argument(f"--{role}-base-url")
        parser.add_argument(f"--{role}-api-key")
        parser.add_argument(f"--{role}-model")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = run_campaign(args)
    print(json.dumps(report, indent=2, sort_keys=True))


def run_campaign(args: argparse.Namespace) -> dict[str, Any]:
    if args.steps != 2:
        raise ValueError("DS-29 campaign smoke currently requires --steps 2")
    args.out.mkdir(parents=True, exist_ok=True)
    campaign_id = f"ds29-seed-{args.seed}-{int(time.time())}"
    endpoints = configured_endpoints(args)
    preflight_results = [] if args.sdk_mode == "adapter" else preflight(endpoints, chat_timeout=args.chat_timeout)
    sessions = _session_ids(campaign_id)
    session_db = args.out / "agents-sdk-sessions.sqlite"
    actors = _actors(args, endpoints, sessions, session_db, campaign_id)
    memory = CampaignMemoryStore()
    steps: list[dict[str, Any]] = []
    memory_effects: list[dict[str, Any]] = []
    started = time.perf_counter()
    for step in range(1, 3):
        trace_path = args.out / f"step-{step}.jsonl"
        env = MissionDeskEnv(trace_path, seed=args.seed + step - 1, service_url=args.service_url, scenario=args.scenario)
        prepare_live_schedule(env)
        env.trace.emit(
            "state_transition",
            env.now,
            {
                "kind": "campaign_step_started",
                "campaign_id": campaign_id,
                "step": step,
                "memory_mode": "campaign",
                "sdk_session_ids": sessions,
                "sdk_mode": "direct_sdk" if args.sdk_mode == "direct" else "adapter_fallback",
            },
        )
        decisions = _run_step(env, actors, memory, step)
        env.run(args.until)
        replay_score = derive_scores(load_trace(trace_path))
        trace_events = load_trace(trace_path)
        score = _last_score(trace_events)
        replay_ok = replay_score == {k: v for k, v in score.items() if k != "evidence"}
        if not replay_ok:
            raise RuntimeError(f"replay mismatch for {trace_path}")
        for event in trace_events:
            if event["type"] == "llm_decision":
                fact = memory_fact_from_decision(event, visible_at_step=step + 1)
                memory.add(
                    type(fact)(
                        role=fact.role,
                        visible_at_step=fact.visible_at_step,
                        source_event_ids=fact.source_event_ids,
                        summary=fact.summary,
                        action=fact.action,
                        decision_event_id=fact.decision_event_id,
                        source_trace_path=str(trace_path),
                    )
                )
        if step == 2:
            memory_effects = _memory_effects(trace_events)
        steps.append(
            {
                "step": step,
                "trace_path": str(trace_path),
                "replay_ok": replay_ok,
                "replay_score": replay_score,
                "score": score,
                "sdk_session_ids": sessions,
                "decisions": decisions,
                "decision_quality": decision_quality_report(trace_events),
            }
        )
    report_path = args.out / "campaign-report.json"
    report = {
        "campaign_id": campaign_id,
        "status": "completed",
        "harness_version": HARNESS_VERSION,
        "sdk_mode": "direct_sdk" if args.sdk_mode == "direct" else "adapter_fallback",
        "memory_mode": "campaign",
        "seed": args.seed,
        "until": args.until,
        "report_path": str(report_path),
        "cache_path": str(args.out / "cache"),
        "sdk_session_db": str(session_db),
        "sdk_session_ids": sessions,
        "preflight": preflight_results,
        "advertised_context_tokens_by_role": _preflight_by_role(preflight_results, "advertised_context_tokens"),
        "served_context_tokens_by_role": _preflight_by_role(preflight_results, "served_context_tokens"),
        "served_context_evidence_by_role": _preflight_by_role(preflight_results, "served_context_evidence"),
        "steps": steps,
        "role_memory": {role: [fact.as_observation_item() for fact in facts] for role, facts in memory.facts.items()},
        "step2_memory_effects": memory_effects,
        "replay": {"ok": all(step["replay_ok"] for step in steps), "score": steps[-1]["replay_score"]},
        "score_summary": steps[-1]["score"],
        "qualitative_output_checklist": _qualitative_outputs(load_trace(Path(steps[-1]["trace_path"]))),
        "telemetry": _telemetry_summary([load_trace(Path(step["trace_path"])) for step in steps]),
        "failure_classification": "none",
        "wall_clock_s": round(time.perf_counter() - started, 6),
        "canonicality": {
            "score_source": "Badlands JSONL trace",
            "sdk_sessions_required_for_replay": False,
        },
    }
    if not memory_effects:
        raise RuntimeError("step 2 did not produce a trace-backed role memory effect")
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True))
    return report


def _session_ids(campaign_id: str) -> dict[str, str]:
    return {role: f"{campaign_id}-{role}-session" for role in ROLE_ORDER}


def _preflight_by_role(preflight_results: list[dict[str, Any]], key: str) -> dict[str, Any]:
    return {item["role"]: item.get(key) for item in preflight_results}


def _actors(
    args: argparse.Namespace,
    endpoints: dict[str, RoleEndpoint],
    sessions: dict[str, str],
    session_db: Path,
    campaign_id: str,
) -> dict[str, Any]:
    cache_dir = args.out / "cache"
    actor_classes = {"green": GreenUserLLM, "attacker": AttackerLLM, "defender": DefenderLLM}
    actors: dict[str, Any] = {}
    for role, actor_cls in actor_classes.items():
        if args.sdk_mode == "adapter":
            client = DeterministicCampaignClient(role=role, session_id=sessions[role], campaign_id=campaign_id)
        else:
            cfg = endpoints[role]
            client = AgentsSdkCompatClient(
                role=role,
                base_url=cfg.base_url,
                api_key=cfg.api_key,
                model=cfg.model,
                session_id=sessions[role],
                session_db_path=session_db,
                campaign_id=campaign_id,
                trace_id=f"trace-{campaign_id}-{role}",
            )
        actors[role] = actor_cls(cache_dir=cache_dir, seed=args.seed, client=client, model=client.model)
    return actors


def _run_step(
    env: MissionDeskEnv,
    actors: dict[str, Any],
    memory: CampaignMemoryStore,
    step: int,
) -> list[dict[str, Any]]:
    env.run(0)
    visible_memory = {role: _emit_visible_memory(env, memory, role, step) for role in ROLE_ORDER}
    observations = {
        "green": _green_observation(env, 0),
        "attacker": attacker_view(env.trace.events),
        "defender": env.defender_observation(),
    }
    decisions: list[dict[str, Any]] = []
    for role in ROLE_ORDER:
        observation = add_campaign_memory(observations[role], visible_memory[role])
        try:
            decision = actors[role].decide(observation)
        except InvalidLLMDecision as exc:
            env.trace.emit(
                "llm_decision_invalid",
                env.now,
                {
                    "role": role,
                    "raw_decision": exc.raw,
                    "reason": exc.reason,
                    "observation": observation,
                    "inference_telemetry": exc.telemetry,
                },
                agent=role,
            )
            decisions.append({"role": role, "status": "invalid", "reason": exc.reason})
            continue
        event_id = env.trace.emit("llm_decision", env.now, decision.trace_payload(role, observation), agent=role, parents=decision.evidence_ids)
        _apply_decision(env, role, decision, event_id)
        decisions.append({"role": role, "status": "valid", "event_id": event_id, "action": decision.action})
    return decisions


def _emit_visible_memory(
    env: MissionDeskEnv,
    memory: CampaignMemoryStore,
    role: str,
    step: int,
) -> dict[str, Any]:
    visible = memory.observation_memory(role, step=step)
    facts = []
    visible_event_ids = []
    for fact in visible["facts"]:
        eid = env.trace.emit(
            "state_transition",
            env.now,
            {
                "kind": "campaign_memory_visible",
                "campaign_step": step,
                "role": role,
                "summary": fact["summary"],
                "action": fact["action"],
                "upstream_source_event_ids": fact["source_event_ids"],
                "upstream_source_trace_path": fact.get("source_trace_path"),
                "upstream_decision_event_id": fact.get("decision_event_id"),
            },
            agent=role,
        )
        visible_event_ids.append(eid)
        upstream_ref = f"{fact.get('source_trace_path')}#{fact.get('decision_event_id')}"
        facts.append(
            {
                **fact,
                "decision_event_id": eid,
                "source_event_id": eid,
                "source_event_ids": [eid],
                "upstream_decision_ref": upstream_ref,
                "upstream_source_event_ids": fact["source_event_ids"],
            }
        )
    return {
        "mode": visible["mode"],
        "step": step,
        "facts": facts,
        "source_event_id": visible_event_ids[0] if visible_event_ids else None,
        "source_event_ids": visible_event_ids,
    }


def _green_observation(env: MissionDeskEnv, task_index: int) -> dict[str, Any]:
    task = env._green_workflow_task(task_index, {})
    required_role = str(task.get("required_role", "mission_analyst"))
    users = [user_id for user_id, user in env.state.users.items() if user.role == required_role] or list(env.state.users)
    user = users[task_index % len(users)]
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


def _apply_decision(env: MissionDeskEnv, role: str, decision: LLMDecision, decision_event_id: str) -> None:
    if role == "green":
        env.green_task(0, selected_action=decision.action, selected_parameters=decision.parameters, decision_event_id=decision_event_id)
    elif role == "attacker":
        env.attacker(decision.action, decision.parameters, decision_event_id=decision_event_id)
        env.run(env.now + ATTACKER_ACTION_DURATIONS[decision.action])
    elif role == "defender":
        env.defender(decision.action, decision.parameters, decision_event_id=decision_event_id)
        env.run(env.now + DEFENDER_ACTION_DURATIONS[decision.action])


def _last_score(events: list[dict[str, Any]]) -> dict[str, Any]:
    scores = [event["payload"] for event in events if event["type"] == "score_snapshot"]
    if not scores:
        raise RuntimeError("score_snapshot missing from campaign trace")
    return scores[-1]


def _memory_effects(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    effects = []
    for event in events:
        if event["type"] != "llm_decision":
            continue
        memory = event["payload"].get("observation", {}).get("campaign_memory", {})
        source_ids = memory.get("source_event_ids", [])
        evidence_ids = event["payload"].get("evidence_ids", [])
        if memory.get("facts") and set(evidence_ids).intersection(source_ids):
            effects.append(
                {
                    "role": event.get("agent"),
                    "decision_event_id": event["event_id"],
                    "memory_source_event_ids": sorted(set(evidence_ids).intersection(source_ids)),
                    "evidence": event["payload"].get("rationale"),
                    "action": event["payload"].get("action"),
                }
            )
    return effects


def _qualitative_outputs(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {role: [] for role in ROLE_ORDER}
    for event in events:
        if event["type"] not in {"llm_decision", "llm_decision_invalid"}:
            continue
        payload = event["payload"]
        raw = payload.get("raw_decision", {})
        telemetry = payload.get("inference_telemetry", {})
        out[str(event.get("agent"))].append(
            {
                "event_id": event["event_id"],
                "event_type": event["type"],
                "action": raw.get("action"),
                "intent": raw.get("intent"),
                "rationale": raw.get("rationale"),
                "expected_effect": raw.get("expected_effect"),
                "risk": raw.get("risk"),
                "raw_outputs": raw.get("raw_outputs") or telemetry.get("raw_outputs", []),
                "campaign_memory_source_ids": payload.get("observation", {}).get("campaign_memory", {}).get("source_event_ids", []),
            }
        )
    return out


def _telemetry_summary(traces: list[list[dict[str, Any]]]) -> dict[str, Any]:
    items = [
        event["payload"].get("inference_telemetry", {})
        for events in traces
        for event in events
        if event["type"] in {"llm_decision", "llm_decision_invalid"}
    ]
    by_role = {}
    for role in ROLE_ORDER:
        role_items = [item for item in items if item.get("role") == role]
        by_role[role] = {
            "decisions": len(role_items),
            "completion_tokens": sum(int(item.get("completion_tokens") or 0) for item in role_items),
            "attempts": sum(int(item.get("attempt_count") or 0) for item in role_items),
            "repairs": sum(int(item.get("repair_count") or 0) for item in role_items),
            "invalid": sum(int(item.get("final_invalid_count") or 0) for item in role_items),
            "sdk_session_ids": sorted({str(item.get("sdk_session_id")) for item in role_items if item.get("sdk_session_id")}),
        }
    return {
        "decisions": len(items),
        "completion_tokens": sum(int(item.get("completion_tokens") or 0) for item in items),
        "attempts": sum(int(item.get("attempt_count") or 0) for item in items),
        "repairs": sum(int(item.get("repair_count") or 0) for item in items),
        "invalid_decisions": sum(int(item.get("final_invalid_count") or 0) for item in items),
        "wall_latency_s": round(sum(float(item.get("wall_latency_s") or 0.0) for item in items), 6),
        "per_role": by_role,
    }


if __name__ == "__main__":
    main()
