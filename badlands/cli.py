from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable

from badlands.agents.baselines import POLICIES
from badlands.agents.llm import AttackerLLM, DefenderLLM, InvalidLLMDecision, LLMDecision
from badlands.agents.user_simulator import CachedReplayUserSimulator
from badlands.core.attacker_actions import ATTACKER_ACTION_DURATIONS
from badlands.core.defender_actions import DEFENDER_ACTION_DURATIONS
from badlands.core.env import MissionDeskEnv
from badlands.core.observations import attacker_view

ATTACK_DURATIONS = ATTACKER_ACTION_DURATIONS
DEFENDER_DURATIONS = DEFENDER_ACTION_DURATIONS


def _invalid_llm(env: MissionDeskEnv, role: str, exc: InvalidLLMDecision, observation: dict[str, Any]) -> None:
    env.trace.emit(
        "llm_decision_invalid",
        env.now,
        {"role": role, "raw_decision": exc.raw, "reason": exc.reason, "observation": observation},
        agent=role,
    )


def _valid_llm(env: MissionDeskEnv, role: str, observation: dict[str, Any], decision: LLMDecision) -> str:
    return env.trace.emit(
        "llm_decision",
        env.now,
        decision.trace_payload(role, observation),
        agent=role,
        parents=decision.evidence_ids,
    )


def schedule_llm_attacker(env: MissionDeskEnv, actor: Any, *, max_actions: int = 6) -> None:
    _schedule_llm_actor(
        env,
        actor,
        role="attacker",
        max_decisions=max_actions,
        observe=lambda: attacker_view(env.trace.events),
        apply=lambda decision, decision_event_id: env.attacker(
            decision.action,
            decision.parameters,
            decision_event_id=decision_event_id,
        ),
        durations=ATTACK_DURATIONS,
        retry_delay=2,
        action_gap=1,
        first_delay=0,
    )


def schedule_llm_defender(env: MissionDeskEnv, actor: Any, *, max_decisions: int = 5, first_delay: int = 10) -> None:
    _schedule_llm_actor(
        env,
        actor,
        role="defender",
        max_decisions=max_decisions,
        observe=env.defender_observation,
        apply=lambda decision, decision_event_id: env.defender(
            decision.action,
            decision.parameters,
            decision_event_id=decision_event_id,
        ),
        durations=DEFENDER_DURATIONS,
        retry_delay=5,
        action_gap=5,
        first_delay=first_delay,
    )


def _schedule_llm_actor(
    env: MissionDeskEnv,
    actor: Any,
    *,
    role: str,
    max_decisions: int,
    observe: Callable[[], dict[str, Any]],
    apply: Callable[[LLMDecision, str], None],
    durations: dict[str, int],
    retry_delay: int,
    action_gap: int,
    first_delay: int,
) -> None:
    def tick(remaining: int) -> None:
        if remaining <= 0:
            return
        observation = observe()
        try:
            decision: LLMDecision = actor.decide(observation)
        except InvalidLLMDecision as exc:
            _invalid_llm(env, role, exc, observation)
            env.schedule(retry_delay, lambda: tick(remaining - 1))
            return
        decision_event_id = _valid_llm(env, role, observation, decision)
        apply(decision, decision_event_id)
        env.schedule(durations[decision.action] + action_gap, lambda: tick(remaining - 1))

    env.schedule(first_delay, lambda: tick(max_decisions))


def run_episode(args: argparse.Namespace) -> dict:
    user_sim = CachedReplayUserSimulator(args.llm_cache, args.seed) if args.green_actor == "llm" else None
    env = MissionDeskEnv(
        args.trace,
        seed=args.seed,
        no_persistence=args.no_persistence,
        no_green=args.no_green,
        no_noise=getattr(args, "no_noise", False),
        perfect_sensors=getattr(args, "perfect_sensors", False),
        magic_observations=args.magic_observations,
        service_url=args.service_url,
        user_simulator=user_sim,
        scenario=getattr(args, "scenario", None),
    )
    if args.attacker_actor == "llm":
        schedule_llm_attacker(env, AttackerLLM(cache_dir=args.llm_cache, seed=args.seed))
    else:
        actions = [
            "discover_local",
            "scan_network",
            "attempt_credential_access",
            "establish_persistence",
            "lateral_move",
            "collect",
            "exfiltrate",
            "disrupt_service",
        ]
        for idx, action in enumerate(actions):
            env.schedule(idx * 2, lambda action=action: env.attacker(action))
    if args.defender_actor == "llm":
        schedule_llm_defender(env, DefenderLLM(cache_dir=args.llm_cache, seed=args.seed))
    else:
        def apply_policy() -> None:
            observation = env.defender_observation()
            actions = (
                [("isolate_host", {"host_id": env.state.attacker_host})]
                if args.magic_observations
                else POLICIES[args.defender](observation, seed=args.seed, magic=False)
            )
            for idx, (action, params) in enumerate(actions):
                env.schedule(idx * 4, lambda action=action, params=params: env.defender(action, params))
        env.schedule(12, apply_policy)
        env.schedule(20, apply_policy)
    return env.run(args.until)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace", type=Path, default=Path("runs/mission-desk-trace.jsonl"))
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--until", type=int, default=60)
    ap.add_argument("--defender", choices=sorted(POLICIES), default="evidence_gathering")
    ap.add_argument("--no-persistence", action="store_true")
    ap.add_argument("--no-green", action="store_true")
    ap.add_argument("--no-noise", action="store_true")
    ap.add_argument("--perfect-sensors", action="store_true")
    ap.add_argument("--magic-observations", action="store_true")
    ap.add_argument("--service-url")
    ap.add_argument("--scenario", type=Path)
    ap.add_argument("--llm-cache", type=Path, default=Path("tests/fixtures/llm_cache"))
    ap.add_argument("--green-actor", choices=["scripted", "llm"], default="scripted")
    ap.add_argument("--attacker-actor", choices=["scripted", "llm"], default="scripted")
    ap.add_argument("--defender-actor", choices=["baseline", "llm"], default="baseline")
    args = ap.parse_args()
    score = run_episode(args)
    print(json.dumps({"trace": str(args.trace), "score": score}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
