# Canonical Validation Matrix

Use this matrix to decide what is enough for each autonomous issue. Passing
unit tests alone is never enough for environment-validity claims.

## Baseline gates for every issue

```bash
cd /Users/jarrodbarnes/badlands
uv run --extra dev ruff check badlands tests
uv run --extra dev python -m pytest -q
```

If an issue changes runtime behavior, also run a seeded trace and replay:

```bash
uv run badlands-episode --seed 7 --trace runs/<issue>-smoke.jsonl
uv run badlands-replay runs/<issue>-smoke.jsonl
```

## Matrix

| Change type | Required validation | Evidence artifact | Reviewer focus |
|---|---|---|---|
| Environment behavior | Unit tests, seeded episode, replay, trace inspection | JSONL trace with relevant event ids | Causality, no decorative state, mission/security effect |
| Service authority | Integration test against active service, replay | service telemetry, mission/security events | Python does not silently replace service truth |
| Scoring | Replay test, score evidence inspection | `score_snapshot.evidence` | Every nonzero field cites source events |
| Observation surface | Role-view tests, leak guards | `observation_delivered`, role observations | No hidden labels, scorer truth, future schedules |
| Action surface | Precondition/success/failure/duration tests | `action_requested`, `action_started`, `action_completed` | No no-op actions; side effects are observable |
| Noise/sensor model | Directional ablation tests | no-noise/perfect-sensor traces | Uncertainty changes decisions/outcomes |
| Live LLM behavior | DS-24 harness, replay, qualitative report | live trace, live report, cache path | Role isolation, invalid decisions, token/latency/retry cost |
| Prompt/rubric changes | Fixture tests plus at least one live-output review | rubric report, model-output excerpts | Valid JSON is not enough; inspect behavior |
| Capability-curve metadata | Ledger/schema validation plus report inspection | run ledger entry, report metadata | Model, endpoint, scaffold, memory, tool surface, scenario, budget, comparison axis, served context |
| Campaign/memory | Replay without SDK/session state, negative leak tests | campaign trace, SDK correlation metadata | SDK memory is role-isolated and non-canonical |
| Docs/provenance | Source/path existence checks | updated docs and links | Implemented evidence versus aspiration |
| Calibration | Calibration schema tests and report fields | calibration records | No fake precision; unknowns are explicit |

## Live inference gates

Use `docs/dgx-spark-live-inference.md` and `badlands-live-validate` for every
remaining environment-roadmap issue unless the issue is strictly docs-only.
It is mandatory for any issue that changes LLM observations, prompts, action
surfaces, live harness behavior, scoring behavior, or qualitative review.

A live run must produce:

- completed trace with `score_snapshot`;
- replay success;
- report path and cache path;
- endpoint topology;
- per-role token, latency, attempt, repair, and invalid-decision telemetry;
- capability-curve metadata required by `docs/capability-curve-contract.md`;
- effective served context by role for campaign or long-horizon runs;
- qualitative model-output summary.

Endpoint saturation is an infrastructure blocker, not an environment failure,
but it must be named precisely.
Do not treat 32K smoke context as representative long-horizon capability
evidence.

During overnight execution, live validation is not optional. If endpoint
availability blocks live validation, stop with a precise blocker rather than
approving offline-only evidence.

## Trace evidence requirements

Claims about mission harm, security harm, defense quality, noise, degraded
service state, or objective progress must cite event ids. Prefer explicit
parents/source-event references over prose.

Minimum useful trace excerpt for review:

- triggering action or scheduled green event;
- service or dependency state change;
- telemetry or alert artifact;
- mission/security/defense impact event;
- score snapshot evidence reference.

## Stop/go gates

Go to review when:

- all relevant validation rows pass;
- trace and report artifacts are named;
- residual risks are downstream scope, not acceptance failures.

Stop before review when:

- an advertised ablation is unimplemented;
- replay fails;
- score evidence is missing;
- hidden state reaches a role observation;
- live harness passes without `score_snapshot`;
- invalid LLM behavior is silently repaired or coerced.
