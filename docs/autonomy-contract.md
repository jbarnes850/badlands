# Badlands Autonomy Contract

This is the canonical operating contract for autonomous Codex execution on
Badlands. Linear remains the task source of truth. This repo remains the context
source of truth.

## Mission charter

Mission owners need continuous, affordable, mission-realistic cyber self-play
measurement: always-on environments where co-evolving attacker and defender
agents stress-test mission systems under realistic operational constraints, so
leaders can see how cyber risk changes as model capability, test-time compute,
cost, and system state evolve.

Boiled down: always-on cyber self-play is only useful if the environment is
realistic enough to expose mission-relevant failure modes, measurable enough to
compare capability over time, and cheap enough to run continuously.

Badlands is currently in the environment-validity phase. Optimize every issue
for construct-valid measurement, not agent cleverness.

## Non-negotiable invariants

- Badlands JSONL trace is canonical for environment state, replay, and scoring.
- Scores must cite trace evidence. No direct score increments without source
  events.
- Observations are role-valid. No hidden labels, future schedules, scorer truth,
  attacker truth, or privileged service state in agent observations.
- Mission realism comes before agent sophistication.
- The environment is the rich part. The live actor loop stays simple and
  observable.
- Live model behavior must be inspected qualitatively, not only schema-checked.
- Invalid, brittle, or degenerate model behavior is measurement signal. Do not
  silently coerce it into success.
- DS-29 owns durable memory, campaign continuity, OpenAI Agents SDK sessions,
  and compaction. Earlier issues must not rebuild those primitives.
- Co-evolution currently means only within-run adaptation through role memory
  and across-episode adaptation through campaign state. Prompt/scaffold/tool
  self-improvement is future scope.
- Capability-curve runs must record the comparison axis, model ids, endpoints,
  scaffold, memory mode, tool surface, scenario version, token budget,
  wall-clock budget, cost/power class, and served context. See
  `docs/capability-curve-contract.md`.
- No unsafe offensive tooling. Actors may only operate through Badlands
  role-valid action surfaces.
- Provenance and calibration claims must distinguish implemented evidence from
  future validation plans.

## Layering order

1. Environment richness: active services, realistic users, dependencies, noisy
   telemetry, meaningful attacker and defender actions.
2. Measurement and ablation: trace evidence, scoring, directional ablations,
   validation reports.
3. Long-horizon agents: role-isolated campaign memory and continuity through the
   OpenAI Agents SDK.
4. Capability curves: compare model, tokens, memory, harness, scenario, served
   context, wall-clock, and cost/power axes without hidden confounders.
5. Provenance and calibration: explicit source/citation/calibration status for
   realism claims.

Do not invert this order without a decision-log entry and Linear comment.

## Autonomous execution loop

For each issue, the night-shift Codex should:

1. Read this contract, `docs/execution-roadmap.md`,
   `docs/validation-matrix.md`, `docs/capability-curve-contract.md`, the
   Linear issue, and the issue's required source pack.
2. Inspect relevant current code and docs before editing.
3. Execute the issue exactly within scope.
4. Add or update tests and docs in the same slice.
5. Run the required validation gates from `docs/validation-matrix.md`.
6. Append meaningful runs to the run ledger format in
   `docs/run-ledger.md`.
7. Produce a reviewer-ready completion note with artifacts, commands, trace
   paths, report paths, and residual risks.
8. Request an independent reviewer/subagent pass.
9. Continue only after reviewer approval; stop before the next issue if a stop
   condition is hit.

## Stop conditions

Stop and request review instead of improvising when:

- A change would weaken trace/replay canonicality.
- A role observation needs hidden state to pass.
- A score cannot be recomputed from trace evidence.
- A live run cannot produce `score_snapshot` and replay.
- The implementation would require custom durable memory, campaign state, or
  compaction before DS-29.
- An issue requires arbitrary shell/tool access for attacker, defender, or
  green actors.
- A realism claim has no source, local artifact, or explicit validation plan.
- The same fix fails twice. Re-diagnose from first principles before a third
  attempt.
- The issue's acceptance criteria require expanding another issue's scope.

## Planner protocol

The planner should produce a compact execution prompt, not a sprawling design.
It should include:

- issue id and Linear URL;
- why this issue is next;
- likely files touched;
- risk areas;
- required tests;
- live validation plan;
- expected artifacts;
- out-of-scope boundaries;
- dependency and defer notes.

The planner should not add features beyond the issue contract.

## Executor protocol

The executor owns implementation. It should:

- keep diffs scoped to the issue;
- preserve existing passing behavior unless the issue explicitly changes it;
- use real service/trace paths instead of mocks for readiness claims;
- keep actor loops thin and role-action bounded;
- report exact commands, outputs, traces, reports, and blockers.

## Reviewer protocol

The independent reviewer/subagent is the overnight approval authority for
normal issue-by-issue progression. The executor may not self-certify.

Reviewer output is findings-first:

1. `APPROVED` or `NOT APPROVED`.
2. Findings ordered P1/P2/P3 with file and line references.
3. Validation commands run.
4. Trace/report evidence reviewed.
5. Live model-output review when applicable.
6. Acceptance criteria check.
7. Downstream readiness.
8. Residual risks only for acceptable deferrals.

Reviewers must look for:

- hidden-state leakage;
- score fields without trace evidence;
- no-op actions;
- overbroad abstractions;
- custom agent-framework work before DS-29;
- replay nondeterminism;
- live-output brittleness hidden by schema validity;
- environment claims unsupported by data, source, or calibration plan.

## Night-shift rule

Autonomous Codex may execute the ordered lane in
`docs/execution-roadmap.md`, but only one issue at a time. It may continue to
the next issue after all tests, replay, docs, live validation, run ledger,
Linear update, and reviewer approval for the current issue are complete. It
must stop if any stop condition fires.
