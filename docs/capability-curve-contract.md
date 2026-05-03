# Capability Curve Contract

This contract defines how Badlands should measure cyber agent capability over
time. It exists to prevent long-horizon runs from becoming incomparable piles
of traces.

## Core definition

Capability is not model-alone.

```text
capability =
  model
  + tools
  + memory
  + harness
  + search policy
  + self-improvement loop
  + compute budget
```

Badlands must therefore measure the full agent system, not only the served
model. Any claim that capability improved must state which component changed
and which components were held constant.

## First principle

Environment validity comes first. If the world is toy-like, every later
capability curve is fake.

The early Badlands work should prove that the environment exposes
mission-relevant failure modes under persistent state, realistic observations,
green/user activity, timing, false positives, mission disruption, and
trace-backed scoring. Capability curves become meaningful only after this
substrate can produce construct-valid measurement signal.

## Independent variables

Capability-curve runs should vary one primary axis at a time whenever possible.
Every run must record the active values for these axes:

- `model_id_by_role`: attacker, defender, and green model ids.
- `endpoint_by_role`: endpoint URL and serving runtime per role.
- `token_budget`: prompt, completion, repair, and total budget where available.
- `wall_clock_budget`: configured runtime budget and actual elapsed time.
- `memory_mode`: none, trace-only, retrieved summaries, SDK session, or campaign
  memory.
- `retrieval_mode`: none, fixed-window, event-id retrieval, case retrieval, or
  hybrid.
- `compaction_mode`: none, fixed summary, evidence-preserving summary, or SDK
  managed.
- `tool_surface_id`: the allowed Badlands action/tool surface available to each
  role.
- `harness_version`: commit or explicit harness id.
- `scenario_id`: scenario fixture or campaign scenario family.
- `scenario_complexity`: configured scale/difficulty descriptor.
- `search_policy`: single sample, repair-only, parallel samples, verifier pass,
  rollout search, or other explicit policy.
- `self_improvement_mode`: none, offline human update, scaffold update, prompt
  update, tool update, or model update.
- `inference_topology`: local/DGX/cloud endpoint topology and role placement.
- `cost_estimate`: dollars or local cost proxy when available.
- `power_or_device_class`: local edge/server class when local inference economics
  matter.

## Dependent variables

Badlands should track capability through mission and security outcomes, not
only task completion.

Primary dependent variables:

- mission score;
- security score;
- attacker objective progress;
- time-to-compromise;
- time-to-containment;
- attacker dwell time;
- mission tasks completed and failed;
- false-positive harm;
- mission disruption;
- service downtime;
- user lockout or harmful-defense time;
- exfiltration or sensitive collection units;
- persistence duration;
- invalid decision rate;
- repair count and repair-invalid count;
- output tokens/sec;
- wall-clock latency by role;
- cost per useful progress unit.

Qualitative dependent variables:

- strategy change summary;
- repeated or degenerate action patterns;
- evidence-grounding quality;
- hidden-state or unsupported-claim rate;
- defender blast-radius reasoning;
- green/user realism under mission pressure;
- attacker stealth, staging, and objective pursuit;
- co-evolution signal versus simple repetition.

## Run tiers

Use increasing run tiers. Do not skip directly to long runs before lower tiers
are replayable and inspectable.

| Tier | Purpose | Minimum evidence |
|---|---|---|
| smoke | Fast correctness check | trace, replay, score snapshot |
| bounded-live | DS-24-style live model validation | trace, replay, report, qualitative review |
| 1-hour liveness | Always-on systems check | completed campaign window, no drift in trace/replay |
| 3-hour continuity | Memory and scenario continuity | role-isolated memory evidence, strategy continuity |
| 6-hour co-evolution | Early co-evolution proof | strategy changes, mission/security deltas, budget accounting |
| overnight/weekly | Always-on eval substrate | comparable ledger entries across time and versions |

Each tier must preserve replay from Badlands JSONL without requiring live model,
cache, or SDK session state.

## Comparability rule

Every capability run must version enough context to make comparisons valid:

- environment commit;
- scenario fixture or scenario hash;
- model ids by role;
- endpoint/runtime versions;
- harness version;
- memory mode;
- retrieval and compaction modes;
- tool/action surface;
- search policy;
- token and wall-clock budgets;
- cost/power proxy;
- run tier;
- seed set;
- baseline run id or comparison group id.

If any of these change, the report must say whether the run is a controlled
comparison, an exploratory run, or an incomparable infrastructure check.

## Co-evolution rule

Co-evolution must be named precisely. Separate these modes:

- `within_run_adaptation`: actors adapt inside one trace using role-visible
  observations.
- `cross_episode_memory`: actors carry role-visible facts across episodes.
- `scaffold_evolution`: prompts, wrappers, retrieval, or orchestration change
  between runs.
- `tool_surface_evolution`: available Badlands actions or tools change.
- `scenario_evolution`: environment scenarios change in response to observed
  failures.
- `model_evolution`: model ids, weights, fine-tunes, or serving parameters
  change.

For the current Badlands lane, co-evolution means only:

1. within-run adaptation through role memory;
2. across-episode adaptation through campaign state.

Before DS-29, Badlands should only measure within-run behavior and live
decision quality. DS-29 owns role-isolated campaign memory and should use the
OpenAI Agents SDK where possible. Later long-horizon work may add scaffold,
tool, scenario, or model evolution, but each must be versioned as an explicit
axis rather than hidden inside a run.

Prompt/scaffold self-modification, arbitrary tool invention, agent-authored
scenario mutation, and policy training from prior traces are out of scope for
the current environment lane.

## Served context rule

Served context is a capability axis. It is not an implementation detail.

The current Spark endpoints may be served with 32768-token context for smoke
and liveness validation. That is acceptable only when the run is recorded as a
smoke or liveness run. DS-29 and later 1-hour, 3-hour, and 6-hour campaign runs
must increase and record effective served context by role before the run is
treated as representative long-horizon evidence.

For every live or campaign run, record:

- advertised model context by role;
- effective served context by role;
- evidence source for the served context, such as endpoint metadata, vLLM launch
  config, or serving logs;
- KV pressure, preemptions, endpoint saturation, or explicit unavailable
  markers where metrics are missing.

Do not compare runs with different served context unless `served_context` is
the declared comparison axis.

Long context is not a substitute for memory discipline. Observations and memory
summaries must remain role-valid, trace-linked, and compact enough that the
model is not forced to reason over unbounded transcript sludge.

## Ledger requirements

Capability-curve ledger entries should extend the base run ledger with:

- `capability_curve_group_id`;
- `baseline_run_id`;
- `comparison_axis`;
- `run_tier`;
- `duration_minutes`;
- `model_id_by_role`;
- `endpoint_by_role`;
- `harness_version`;
- `scenario_id`;
- `scenario_complexity`;
- `scenario_version`;
- `fixture_hash`;
- `memory_mode`;
- `retrieval_mode`;
- `compaction_mode`;
- `tool_surface_id`;
- `search_policy`;
- `self_improvement_mode`;
- `token_budget`;
- `wall_clock_budget`;
- `cost_estimate`;
- `power_or_device_class`;
- `advertised_context_tokens_by_role`;
- `served_context_tokens_by_role`;
- `attacker_tokens`;
- `defender_tokens`;
- `green_tokens`;
- `total_completion_tokens`;
- `invalid_decision_rate`;
- `strategy_change_summary`;
- `co_evolution_mode`.

The ledger should make it possible to ask: did risk change because the model
improved, because the harness improved, because memory was enabled, because more
tokens were spent, because the environment changed, or because serving became
faster/cheaper?

## Stop conditions

Stop and mark the run incomparable when:

- the environment or scenario changed without a new comparison group;
- trace replay fails;
- score evidence is missing;
- hidden state enters role memory or observations;
- SDK/session state is required to reproduce the score;
- model, harness, tool surface, memory, and scenario all changed at once;
- cost/token/wall-clock accounting is missing for a claimed capability curve;
- qualitative review shows strategy change cannot be separated from prompt or
  scaffold drift.

## Near-term application

For the current Badlands lane:

- DS-20 through DS-28 build the world whose realism makes curves meaningful.
- DS-27 adds qualitative behavior measurement needed to interpret curves.
- DS-23 creates deterministic ablation reports and comparison structure.
- DS-29 adds role-isolated campaign memory for continuity experiments.
- DS-25 and DS-26 harden provenance and calibration so capability claims do not
  outrun evidence.

Until DS-23 and DS-29 land, capability-curve claims should be described as
preparatory evidence, not final long-horizon measurement.
