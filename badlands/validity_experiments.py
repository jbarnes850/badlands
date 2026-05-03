from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from badlands.cli import run_episode
from badlands.core.observations import FORBIDDEN, defender_view
from badlands.core.trace import load_trace
from badlands.scoring.replay import derive_scores

REPORT_VERSION = "ds23.validity_report.v1"
CURRENT_ABLATIONS = (
    "no_persistence",
    "magic_observations",
    "no_green_users",
    "no_benign_noise",
    "perfect_sensors",
)
PLANNED_ABLATIONS = (
    "instant_actions",
    "synchronous_turns",
    "security_only_scoring",
    "scripted_attacker",
    "no_identity_graph_realism",
)
ALL_ABLATIONS = CURRENT_ABLATIONS + PLANNED_ABLATIONS


@dataclass(frozen=True)
class DirectionalCheck:
    metric: str
    source: str
    expected: str
    minimum_delta: float = 0.0


@dataclass(frozen=True)
class AblationSpec:
    name: str
    claim: str
    virtualization_or_modeling_gap: str
    supported: bool
    baseline_overrides: dict[str, Any] = field(default_factory=dict)
    ablation_overrides: dict[str, Any] = field(default_factory=dict)
    checks: tuple[DirectionalCheck, ...] = ()
    blocker: str | None = None


ABLATIONS: dict[str, AblationSpec] = {
    "no_persistence": AblationSpec(
        name="no_persistence",
        claim="Persistent attacker footholds make dwell and removal timing matter.",
        virtualization_or_modeling_gap="sequence/reward modelling",
        supported=True,
        ablation_overrides={"no_persistence": True},
        checks=(DirectionalCheck("persistence_minutes", "score", "baseline > ablation"),),
    ),
    "magic_observations": AblationSpec(
        name="magic_observations",
        claim="Uncertainty matters; hidden compromise labels should inflate label-following defense.",
        virtualization_or_modeling_gap="observation modelling",
        supported=True,
        baseline_overrides={"defender": "alert_label"},
        ablation_overrides={"defender": "alert_label", "magic_observations": True},
        checks=(DirectionalCheck("true_positive_actions", "score", "ablation > baseline"),),
    ),
    "no_green_users": AblationSpec(
        name="no_green_users",
        claim="Green users create mission harm and false-positive pressure that reject shutdown policies.",
        virtualization_or_modeling_gap="user simulation/reward modelling",
        supported=True,
        baseline_overrides={"defender": "isolate_everything"},
        ablation_overrides={"defender": "isolate_everything", "no_green": True},
        checks=(DirectionalCheck("mission_tasks_failed", "score", "baseline > ablation"),),
    ),
    "no_benign_noise": AblationSpec(
        name="no_benign_noise",
        claim="Benign noise creates false-positive and analyst-cost pressure.",
        virtualization_or_modeling_gap="observation modelling",
        supported=True,
        ablation_overrides={"no_noise": True},
        checks=(
            DirectionalCheck("false_positive_actions", "score", "baseline > ablation"),
            DirectionalCheck("analyst_minutes", "score", "baseline > ablation"),
            DirectionalCheck("alert_count", "trace", "baseline > ablation"),
        ),
    ),
    "perfect_sensors": AblationSpec(
        name="perfect_sensors",
        claim="Sensor coverage, drops, and delay create defender uncertainty.",
        virtualization_or_modeling_gap="observation/sequence modelling",
        supported=True,
        ablation_overrides={"perfect_sensors": True},
        checks=(
            DirectionalCheck("sensor_dropped_count", "trace", "baseline > ablation"),
            DirectionalCheck("sensor_delayed_count", "trace", "baseline > ablation"),
            DirectionalCheck("first_alert_timestamp", "trace", "baseline > ablation"),
        ),
    ),
    "instant_actions": AblationSpec(
        name="instant_actions",
        claim="Action duration and overlap create race conditions.",
        virtualization_or_modeling_gap="sequence/action modelling",
        supported=False,
        blocker="No instant-action scheduler or zero-duration environment mode exists yet.",
    ),
    "synchronous_turns": AblationSpec(
        name="synchronous_turns",
        claim="Event-driven concurrency should differ from fixed alternating turns.",
        virtualization_or_modeling_gap="sequence modelling",
        supported=False,
        blocker="No synchronous-turn scheduler exists yet.",
    ),
    "security_only_scoring": AblationSpec(
        name="security_only_scoring",
        claim="Mission continuity and harmful-defense penalties reject destructive defense.",
        virtualization_or_modeling_gap="reward modelling",
        supported=False,
        blocker="The replay scorer has no mission-penalty-off mode yet.",
    ),
    "scripted_attacker": AblationSpec(
        name="scripted_attacker",
        claim="A deterministic attacker can overstate defender robustness.",
        virtualization_or_modeling_gap="threat simulation",
        supported=False,
        blocker="The default runner already uses a scripted attacker; no variant red policy family exists yet.",
    ),
    "no_identity_graph_realism": AblationSpec(
        name="no_identity_graph_realism",
        claim="LANL-like user-host affinity changes lateral movement and anomaly plausibility.",
        virtualization_or_modeling_gap="network/identity virtualization",
        supported=False,
        blocker="No uniform-auth/no-LANL fixture mode exists yet.",
    ),
}


def run_validity_experiments(args: argparse.Namespace) -> dict[str, Any]:
    selected = _selected_ablations(args.ablations)
    unsupported = [name for name in selected if not ABLATIONS[name].supported]
    if unsupported and not args.allow_unimplemented:
        raise SystemExit(
            "unsupported ablations requested: "
            + ", ".join(f"{name} ({ABLATIONS[name].blocker})" for name in unsupported)
        )

    args.out.mkdir(parents=True, exist_ok=True)
    baseline_runs = [
        _run_case(
            args,
            case_name="full",
            seed=seed,
            overrides={},
            trace_path=args.out / "full" / f"seed-{seed}.jsonl",
        )
        for seed in args.seeds
    ]
    ablations = []
    for name in selected:
        spec = ABLATIONS[name]
        if not spec.supported:
            ablations.append(_unimplemented_result(spec, args.seeds))
            continue
        pair_baselines = [
            _run_case(
                args,
                case_name=f"{name}_baseline",
                seed=seed,
                overrides=spec.baseline_overrides,
                trace_path=args.out / name / "baseline" / f"seed-{seed}.jsonl",
            )
            for seed in args.seeds
        ]
        variants = [
            _run_case(
                args,
                case_name=name,
                seed=seed,
                overrides={**spec.baseline_overrides, **spec.ablation_overrides},
                trace_path=args.out / name / "ablation" / f"seed-{seed}.jsonl",
            )
            for seed in args.seeds
        ]
        ablations.append(_ablation_result(spec, pair_baselines, variants))

    report = {
        "schema_version": REPORT_VERSION,
        "created_at_utc": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "command": " ".join(args.raw_argv) if getattr(args, "raw_argv", None) else None,
        "scenario": str(args.scenario) if args.scenario else "mission_desk_enclave",
        "seeds": args.seeds,
        "seed_count": len(args.seeds),
        "until": args.until,
        "defender": args.defender,
        "actor_modes": {
            "green": args.green_actor,
            "attacker": args.attacker_actor,
            "defender": args.defender_actor,
        },
        "capability_metadata": _capability_metadata(args),
        "baseline": {
            "name": "full",
            "runs": baseline_runs,
            "aggregate_score": _aggregate_scores(baseline_runs),
            "aggregate_trace_metrics": _aggregate_trace_metrics(baseline_runs),
        },
        "ablations": ablations,
        "summary_path": str(args.summary),
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True))
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(_markdown_summary(report))
    return report


def _selected_ablations(value: list[str]) -> list[str]:
    selected: list[str] = []
    for item in value:
        parts = CURRENT_ABLATIONS if item == "current" else ALL_ABLATIONS if item == "all" else tuple(item.split(","))
        for part in parts:
            name = part.strip()
            if not name:
                continue
            if name not in ABLATIONS:
                raise SystemExit(f"unknown ablation {name!r}; known: {', '.join(ALL_ABLATIONS)}")
            if name not in selected:
                selected.append(name)
    return selected


def _run_case(
    args: argparse.Namespace,
    *,
    case_name: str,
    seed: int,
    overrides: dict[str, Any],
    trace_path: Path,
) -> dict[str, Any]:
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    case_args = argparse.Namespace(
        trace=trace_path,
        seed=seed,
        until=args.until,
        defender=overrides.get("defender", args.defender),
        no_persistence=bool(overrides.get("no_persistence", False)),
        no_green=bool(overrides.get("no_green", False)),
        no_noise=bool(overrides.get("no_noise", False)),
        perfect_sensors=bool(overrides.get("perfect_sensors", False)),
        magic_observations=bool(overrides.get("magic_observations", False)),
        service_url=args.service_url,
        scenario=args.scenario,
        llm_cache=args.llm_cache,
        green_actor=args.green_actor,
        attacker_actor=args.attacker_actor,
        defender_actor=args.defender_actor,
    )
    score = run_episode(case_args)
    events = load_trace(trace_path)
    score_snapshots = [event for event in events if event["type"] == "score_snapshot"]
    replay_score = derive_scores(events)
    score_snapshot = {key: value for key, value in score_snapshots[-1]["payload"].items() if key != "evidence"} if score_snapshots else {}
    replay_ok = bool(score_snapshots) and replay_score == score_snapshot == score
    trace_metrics = _trace_metrics(events)
    return {
        "name": case_name,
        "seed": seed,
        "trace_path": str(trace_path),
        "score": score,
        "trace_metrics": trace_metrics,
        "replay": {"ok": replay_ok, "score": replay_score},
        "score_snapshot_present": bool(score_snapshots),
        "score_evidence_missing_fields": _missing_score_evidence(score_snapshots[-1]["payload"]) if score_snapshots else list(score),
        "observation_leak_check": _observation_leak_check(events),
        "overrides": {key: value for key, value in overrides.items() if key != "defender" or value != args.defender},
    }


def _ablation_result(spec: AblationSpec, baselines: list[dict[str, Any]], variants: list[dict[str, Any]]) -> dict[str, Any]:
    runs = []
    for baseline, variant in zip(baselines, variants, strict=True):
        runs.append(
            {
                "seed": variant["seed"],
                "baseline_trace_path": baseline["trace_path"],
                "trace_path": variant["trace_path"],
                "baseline_score": baseline["score"],
                "score": variant["score"],
                "deltas": _deltas(baseline["score"], variant["score"]),
                "trace_metric_deltas": _deltas(baseline["trace_metrics"], variant["trace_metrics"]),
                "baseline_trace_metrics": baseline["trace_metrics"],
                "trace_metrics": variant["trace_metrics"],
                "replay_ok": baseline["replay"]["ok"] and variant["replay"]["ok"],
                "observation_leak_check": {
                    "ok": baseline["observation_leak_check"]["ok"] and variant["observation_leak_check"]["ok"],
                    "baseline": baseline["observation_leak_check"],
                    "ablation": variant["observation_leak_check"],
                },
            }
        )
    checks = [_evaluate_check(check, runs) for check in spec.checks]
    status = _status_from_checks(checks, runs)
    return {
        "name": spec.name,
        "status": status,
        "claim": spec.claim,
        "virtualization_or_modeling_gap": spec.virtualization_or_modeling_gap,
        "supported": True,
        "seeds": [run["seed"] for run in runs],
        "seed_count": len(runs),
        "runs": runs,
        "aggregate_deltas": _aggregate_deltas(runs, "deltas"),
        "aggregate_trace_metric_deltas": _aggregate_deltas(runs, "trace_metric_deltas"),
        "directional_checks": checks,
        "blocker": None,
    }


def _unimplemented_result(spec: AblationSpec, seeds: list[int]) -> dict[str, Any]:
    return {
        "name": spec.name,
        "status": "unimplemented",
        "claim": spec.claim,
        "virtualization_or_modeling_gap": spec.virtualization_or_modeling_gap,
        "supported": False,
        "seeds": seeds,
        "seed_count": len(seeds),
        "runs": [],
        "aggregate_deltas": {},
        "aggregate_trace_metric_deltas": {},
        "directional_checks": [],
        "blocker": spec.blocker,
    }


def _evaluate_check(check: DirectionalCheck, runs: list[dict[str, Any]]) -> dict[str, Any]:
    key = "deltas" if check.source == "score" else "trace_metric_deltas"
    deltas = [float(run[key].get(check.metric, 0.0) or 0.0) for run in runs]
    aggregate = round(sum(deltas) / len(deltas), 6) if deltas else 0.0
    baseline_values = [
        float(
            (run["baseline_score"] if check.source == "score" else run["baseline_trace_metrics"]).get(
                check.metric,
                0.0,
            )
            or 0.0
        )
        for run in runs
    ]
    ablation_values = [
        float(
            (run["score"] if check.source == "score" else run["trace_metrics"]).get(
                check.metric,
                0.0,
            )
            or 0.0
        )
        for run in runs
    ]
    if max([*baseline_values, *ablation_values], default=0.0) == 0.0:
        status = "inconclusive"
    elif _direction_passes(check.expected, aggregate, check.minimum_delta):
        status = "pass"
    else:
        status = "fail"
    return {
        "metric": check.metric,
        "source": check.source,
        "expected": check.expected,
        "observed_delta_by_seed": deltas,
        "observed_aggregate_delta": aggregate,
        "status": status,
    }


def _direction_passes(expected: str, aggregate: float, minimum_delta: float) -> bool:
    if expected == "baseline > ablation":
        return aggregate > minimum_delta
    if expected == "ablation > baseline":
        return aggregate < -minimum_delta
    raise ValueError(f"unsupported expectation {expected}")


def _status_from_checks(checks: list[dict[str, Any]], runs: list[dict[str, Any]]) -> str:
    if not all(run["replay_ok"] and run["observation_leak_check"]["ok"] for run in runs):
        return "fail"
    statuses = {check["status"] for check in checks}
    if statuses == {"pass"}:
        return "pass"
    if "fail" in statuses:
        return "fail"
    return "inconclusive"


def _deltas(baseline: dict[str, Any], ablation: dict[str, Any]) -> dict[str, float]:
    keys = sorted(set(baseline) | set(ablation))
    return {
        key: round(float(baseline.get(key, 0) or 0) - float(ablation.get(key, 0) or 0), 6)
        for key in keys
        if isinstance(baseline.get(key, ablation.get(key)), int | float)
    }


def _aggregate_deltas(runs: list[dict[str, Any]], key: str) -> dict[str, float]:
    metrics = sorted({metric for run in runs for metric in run[key]})
    return {
        metric: round(sum(float(run[key].get(metric, 0.0)) for run in runs) / len(runs), 6)
        for metric in metrics
    } if runs else {}


def _aggregate_scores(runs: list[dict[str, Any]]) -> dict[str, float]:
    metrics = sorted({metric for run in runs for metric in run["score"] if isinstance(run["score"][metric], int | float)})
    return {
        metric: round(sum(float(run["score"][metric]) for run in runs) / len(runs), 6)
        for metric in metrics
    } if runs else {}


def _aggregate_trace_metrics(runs: list[dict[str, Any]]) -> dict[str, float]:
    metrics = sorted({metric for run in runs for metric in run["trace_metrics"]})
    return {
        metric: round(sum(float(run["trace_metrics"].get(metric, 0.0) or 0.0) for run in runs) / len(runs), 6)
        for metric in metrics
    } if runs else {}


def _trace_metrics(events: list[dict[str, Any]]) -> dict[str, Any]:
    alerts = [event for event in events if event["type"] == "alert_emitted"]
    telemetry = [event for event in events if event["type"] == "telemetry_emitted"]
    sensors = [event["payload"].get("sensor", {}) for event in telemetry]
    return {
        "event_count": len(events),
        "alert_count": len(alerts),
        "first_alert_timestamp": min((event["timestamp"] for event in alerts), default=0),
        "sensor_dropped_count": sum(1 for sensor in sensors if sensor.get("dropped")),
        "sensor_delayed_count": sum(
            1
            for event in telemetry
            if event["payload"].get("sensor", {}).get("visible_at") is not None
            and int(event["payload"]["sensor"]["visible_at"]) > int(event["timestamp"])
        ),
        "score_snapshot_count": sum(1 for event in events if event["type"] == "score_snapshot"),
    }


def _missing_score_evidence(score_snapshot: dict[str, Any]) -> list[str]:
    evidence = score_snapshot.get("evidence", {})
    return [
        field
        for field, value in score_snapshot.items()
        if field != "evidence"
        and isinstance(value, int)
        and value != 0
        and not evidence.get(field)
    ]


def _observation_leak_check(events: list[dict[str, Any]]) -> dict[str, Any]:
    text = str(defender_view(events))
    hits = sorted(key for key in FORBIDDEN if key in text)
    return {"ok": not hits, "forbidden_markers": hits}


def _capability_metadata(args: argparse.Namespace) -> dict[str, Any]:
    actor_modes = {
        "green": args.green_actor,
        "attacker": args.attacker_actor,
        "defender": args.defender_actor,
    }
    return {
        "comparison_axis": "environment_ablation",
        "run_tier": "validity_ablation",
        "trace_canonical_source": "Badlands JSONL",
        "memory_mode": "none",
        "campaign_state": "none",
        "tool_surface": "badlands_builtin_actions",
        "token_budget": None,
        "wall_clock_budget_minutes": None,
        "model_by_role": {role: _role_model(role, mode) for role, mode in actor_modes.items()},
        "endpoint_by_role": {role: _role_endpoint(role, args) for role in actor_modes},
    }


def _role_model(role: str, mode: str) -> str:
    if mode not in {"llm", "baseline"}:
        return mode
    if mode == "baseline":
        return "baseline"
    return os.environ.get(f"BADLANDS_{role.upper()}_LLM_MODEL", os.environ.get("BADLANDS_LLM_MODEL", "unknown"))


def _role_endpoint(role: str, args: argparse.Namespace) -> str | None:
    if role == "defender" and args.defender_actor == "baseline":
        return None
    if getattr(args, f"{role}_actor") != "llm":
        return None
    return os.environ.get(f"BADLANDS_{role.upper()}_LLM_BASE_URL", os.environ.get("BADLANDS_LLM_BASE_URL"))


def _markdown_summary(report: dict[str, Any]) -> str:
    lines = [
        "# Badlands Validity Experiment Report",
        "",
        f"- Schema: `{report['schema_version']}`",
        f"- Seeds: `{', '.join(str(seed) for seed in report['seeds'])}`",
        f"- Until: `{report['until']}`",
        f"- Baseline aggregate mission/security/defense: "
        f"`{report['baseline']['aggregate_score'].get('overall_mission_score')}` / "
        f"`{report['baseline']['aggregate_score'].get('overall_security_score')}` / "
        f"`{report['baseline']['aggregate_score'].get('overall_defense_quality_score')}`",
        "",
        "| Ablation | Status | Claim | Key Checks |",
        "|---|---|---|---|",
    ]
    for item in report["ablations"]:
        checks = "; ".join(
            f"{check['metric']} {check['expected']} -> {check['status']} ({check['observed_aggregate_delta']})"
            for check in item.get("directional_checks", [])
        ) or item.get("blocker") or "-"
        lines.append(f"| `{item['name']}` | `{item['status']}` | {item['claim']} | {checks} |")
    lines.extend(["", "## Trace Paths", ""])
    for item in report["ablations"]:
        if not item["runs"]:
            continue
        lines.append(f"### {item['name']}")
        for run in item["runs"]:
            lines.append(f"- seed {run['seed']}: baseline `{run['baseline_trace_path']}`, ablation `{run['trace_path']}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, nargs="+", default=[7])
    parser.add_argument("--until", type=int, default=60)
    parser.add_argument("--out", type=Path, default=Path("runs/validity"))
    parser.add_argument("--report", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--ablations", nargs="+", default=["current"])
    parser.add_argument("--allow-unimplemented", action="store_true")
    parser.add_argument("--defender", default="evidence_gathering")
    parser.add_argument("--service-url")
    parser.add_argument("--scenario", type=Path)
    parser.add_argument("--llm-cache", type=Path, default=Path("tests/fixtures/llm_cache"))
    parser.add_argument("--green-actor", choices=["scripted", "llm"], default="scripted")
    parser.add_argument("--attacker-actor", choices=["scripted", "llm"], default="scripted")
    parser.add_argument("--defender-actor", choices=["baseline", "llm"], default="baseline")
    args = parser.parse_args(raw_argv)
    args.report = args.report or args.out / "validity-report.json"
    args.summary = args.summary or args.out / "validity-summary.md"
    args.raw_argv = ["badlands-validity", *raw_argv]
    return args


def main(argv: list[str] | None = None) -> None:
    report = run_validity_experiments(parse_args(argv))
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
