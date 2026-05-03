# Execution Roadmap

This is the current autonomous execution lane for the Badlands environment
validity project. Linear is authoritative for issue status; this file is the
canonical local context for ordering, dependencies, and drift control.
Use `docs/overnight-runbook.md` as the executable workflow for autonomous
planner/executor/reviewer runs.

Current lane:

```text
DS-20 -> DS-21 -> DS-22 -> DS-28 -> DS-27 -> DS-23 -> DS-29 -> DS-25/DS-26
```

Capability-curve and co-evolution definitions live in
`docs/capability-curve-contract.md`. For the current lane, co-evolution means
only within-run adaptation through role memory and across-episode adaptation
through campaign state. DS-29 owns those mechanics through the OpenAI Agents SDK
where possible.

## Completed substrate

- DS-15: identity provider state is authoritative for auth, reset, sessions,
  and credential use.
- DS-16: Mission Desk world definition moved into scenario fixtures.
- DS-17: mission app, file share, and ticket state are authoritative services.
- DS-18: service dependency graph and outage propagation are causal.
- DS-19: valid and invalid LLM decisions are trace-visible with constrained
  evidence ids.
- DS-24: live inference validation harness exists for role-isolated model
  review, token/latency/retry telemetry, replay, and qualitative inspection.

## DS-20: calibrated benign noise, false positives, and sensor limits

Linear: https://linear.app/mach-10/issue/DS-20/p1-add-calibrated-benign-noise-false-positives-and-sensor-limits

Why now: after DS-24, live model behavior is observable. The next environment
gap is uncertainty. Without benign noise and imperfect sensors, defender
behavior remains a clean classification task.

Unlocks: DS-21 defender workflow, DS-23 no-noise/perfect-sensor ablations, and
credible long-horizon defender behavior under uncertainty.

Must not pull forward: richer defender action workflow, attacker objectives,
campaign memory, or full dataset ingestion.

Deferred ownership: DS-21 owns defender workflow; DS-22 owns attacker
objectives; DS-29 owns campaign memory; DS-25/DS-26 own provenance/calibration
hardening.

Success criteria:

- benign suspicious artifacts appear in trace and defender observations;
- sensor coverage, delay, and dropped events affect observations;
- no-noise and perfect-sensor ablations change expected outcomes;
- alerts and score changes cite source events;
- alert labels alone are insufficient to solve the environment.

Required live verification:

- run DS-24 harness on a bounded live episode;
- inspect whether the defender avoids overreacting to weak/noisy evidence;
- report invalid decisions and retry cost as measurement signal, not failure
  unless the harness breaks.

Required tests:

- noise generation;
- false-positive pressure;
- sensor delay/drop;
- no-noise ablation directionality;
- perfect-sensor ablation directionality;
- observation leak guards.

Stop conditions:

- noise is random junk without mission/workflow provenance;
- hidden labels are needed to classify false positives;
- no-noise/perfect-sensor modes do not materially change observations or
  outcomes.

Review questions:

- Would a classifier solve this from alert names alone?
- Are noisy events plausible green/admin/mission artifacts?
- Are source events cited through scoring and alerts?

## DS-21: realistic defender case workflow

Linear: https://linear.app/mach-10/issue/DS-21/p1-expand-defender-action-surface-into-realistic-case-workflow

Why now: after DS-20, defender uncertainty is real enough that richer defender
workflow has something to reason over.

Unlocks: mission-aware containment, rollback, evidence-gathering policy
comparisons, and better live defender qualitative review.

Must not pull forward: autonomous playbook generation, multi-defender teams,
campaign memory, real EDR/SIEM integration.

Deferred ownership: DS-23 owns systematic ablation; DS-29 owns long-horizon
memory; DS-26 owns calibration hooks.

Success criteria:

- each new/expanded defender action has prerequisites, duration, uncertainty,
  side effects, trace artifacts, and observation results;
- evidence-gathering can outperform premature containment under full scoring;
- harmful defender actions create trace-backed mission/defense penalties;
- prompts and allowed actions remain aligned.

Required live verification:

- run DS-24 harness;
- inspect whether defender uses evidence, considers blast radius, and avoids
  destructive default containment.

Required tests:

- preconditions;
- success/failure/partial success;
- delayed observation artifacts;
- harmful-action mission penalty;
- replay determinism.

Stop conditions:

- actions are no-ops or only API shape;
- actions reveal hidden truth;
- broad containment becomes the dominant policy without mission penalty.

Review questions:

- Does every action have observable consequences?
- Can harmful defense be reconstructed from trace?
- Does defender workflow resemble SOC/mission defense rather than button
  pressing?

## DS-22: attacker objectives for collection, exfiltration, and disruption

Linear: https://linear.app/mach-10/issue/DS-22/p1-add-attacker-objectives-for-collection-exfiltration-and-mission

Why now: after defender uncertainty and workflow exist, attacker objectives
create strategic pressure and multiple viable red paths.

Unlocks: co-evolution pressure, security score depth, objective timing races,
and DS-23 attacker-objective ablations.

Must not pull forward: unsafe exploit execution, internet egress, malware, or
arbitrary shell access.

Deferred ownership: DS-26 owns calibration hooks; DS-29 owns campaign memory;
future epics own full long-horizon capability curves.

Success criteria:

- protected assets are scenario-defined;
- objective success requires plausible prerequisites;
- collection, exfiltration, and disruption emit telemetry, security impact, and
  score evidence;
- defender timing can change objective outcomes;
- no objective success comes from hidden state alone.

Required live verification:

- run DS-24 harness;
- inspect attacker progression for plausible objective pursuit versus repeated
  degenerate actions.

Required tests:

- successful objective path;
- blocked objective path;
- defender race/containment timing;
- trace evidence for objective score fields;
- containment safety boundaries.

Stop conditions:

- implementation requires unsafe offensive tooling;
- objective scoring bypasses trace evidence;
- only one hardcoded objective path exists.

Review questions:

- Are there multiple plausible attacker strategies?
- Are objective artifacts ATT&CK/CALDERA/Mordor/OpTC-aligned or explicitly
  marked heuristic?
- Does the defender have trace-visible ways to detect or recover?

## DS-28: scenario-driven mission workflow service

Linear: https://linear.app/mach-10/issue/DS-28/p1-scale-mission-app-from-hardcoded-demo-into-scenario-driven-mission

Why now: after noise, defender workflow, and attacker objectives, mission
workflows need enough texture to prevent overfitting one tiny task path.

Unlocks: richer green behavior, mission deadlines, workflow queues, dependency
effects, and more meaningful long-horizon runs.

Must not pull forward: full email stack unless needed as minimal stub, broad
synthetic data generation, long-horizon SDK memory.

Deferred ownership: DS-23 owns systematic validity reports; DS-29 owns campaign
continuity; DS-25 owns provenance ledger.

Success criteria:

- scenario-defined workflow with at least three task types and two roles;
- task mix changes trace/score outcomes;
- service-specific degradation/latency affects task success/deadlines;
- ticket backlog or user-facing failures change defender observations and
  mission score;
- green observations show user-experienced outcomes, not hidden truth.

Required live verification:

- run DS-24 harness;
- inspect green model behavior for mission-user realism under task pressure.

Required tests:

- scenario loading;
- workflow task mix;
- deadlines and priorities;
- degradation/latency;
- ticket backlog;
- mission score evidence references.

Stop conditions:

- mission app remains hardcoded behind scenario-shaped wrappers;
- mission score fields cannot cite service telemetry;
- green user becomes SOC analyst-like.

Review questions:

- Are workflows causal and user-facing?
- Can attacker/defender/service state change mission outcomes?
- Does this reduce fixed-benchmark overfitting risk?

## DS-27: role prompt and model-output quality rubric

Linear: https://linear.app/mach-10/issue/DS-27/p1-add-role-prompt-and-model-output-quality-rubric

Why now: once the environment is richer, the rubric can distinguish model
quality from environment validity and avoid judging live behavior by JSON
validity alone.

Unlocks: reliable qualitative review for DS-23, DS-29, and long-horizon
co-evolution reports.

Must not pull forward: automatic model grading, fine-tuning, provider changes,
or safety policy expansion outside contained Badlands actions.

Deferred ownership: DS-24 owns harness telemetry; DS-29 owns campaign memory;
future long-horizon epic owns strategy-change metrics.

Success criteria:

- role-specific rubric exists for attacker, defender, and green;
- live reports summarize repeated actions, evidence quality, hidden-state
  assumptions, mission awareness, blast-radius reasoning, and invalid evidence
  ids;
- fixture tests flag brittle output patterns;
- prompts remain concise and aligned with implemented actions.
- rubric report references `docs/model-output-rubric.md` and remains a
  descriptive reviewer aid rather than an automatic model grade.

Required live verification:

- inspect actual DS-24 live outputs under the rubric;
- separate model brittleness from environment/harness failure.

Required tests:

- repeated attacker action detection;
- defender overreaction detection;
- green SOC-like behavior detection;
- unsupported evidence ids;
- hidden-state claims.

Stop conditions:

- rubric becomes model-intelligence grading rather than environment measurement;
- prompts grow into hidden planners;
- rubric hides invalid behavior instead of surfacing it.

Review questions:

- Does the rubric expose co-evolution signal versus repetition?
- Are evidence ids real trace/observation ids?
- Are model-quality findings separated from implementation defects?

## DS-23: environment validity experiment runner and ablation report

Linear: https://linear.app/mach-10/issue/DS-23/p1-build-environment-validity-experiment-runner-and-ablation-report

Why now: after enough realism dimensions exist, Badlands needs a repeatable
report proving that removing those dimensions changes measured risk.

Unlocks: first environment-validity claim and the bridge to capability-curve
experiments.

Must not pull forward: full 6-hour campaign analysis or publication-grade
statistics unless DS-29 has landed.

Deferred ownership: DS-29 owns campaign continuity; long-horizon epic owns
1-hour/3-hour/6-hour capability-curve reports.

Success criteria:

- one command runs full environment plus supported ablations across seeds;
- report includes score deltas, trace paths, seed count, pass/fail/inconclusive
  status;
- runner fails loudly for advertised but unimplemented ablations;
- no ablation leaks hidden labels into production observation paths.

Required live verification:

- live mode is supported for review gates but optional by default;
- if live mode is run, use DS-24 harness/report semantics.

Required tests:

- report generation;
- at least two directional ablations;
- unimplemented ablation failure;
- trace/replay links.

Stop conditions:

- report is green without meaningful directional evidence;
- ablations test flags rather than virtualisation/modelling-gap claims;
- live model behavior is required for deterministic validity checks.

Review questions:

- Does each ablation test a real modelling/virtualisation claim?
- Are trace links sufficient for replay?
- Does the report make toy incentives visible?

## DS-29: Agents SDK campaign harness

Linear: https://linear.app/mach-10/issue/DS-29/p2-spike-agents-sdk-campaign-harness-with-role-isolated-memory-and

Why now: after the short-horizon world and measurement harness are stable,
Badlands can test role-isolated continuity without inventing custom memory.
This is the first issue allowed to implement the current co-evolution
definition: within-run adaptation through role memory and across-episode
adaptation through campaign state.

Unlocks: 1-hour liveness campaigns, 3-hour continuity runs, and future 6-hour
co-evolution/capability-curve experiments.

Must not pull forward: self-modifying agents, tool-building, arbitrary shell
access, or replacing Badlands trace/replay with SDK traces.

Deferred ownership: long-horizon epic owns 6-hour runs and capability curves;
DS-25/DS-26 own provenance/calibration claims.

Success criteria:

- two-step campaign run with role-isolated SDK sessions or a documented adapter
  fallback;
- step-2 behavior can reflect role-visible memory from step 1;
- campaign state can carry trace-visible prior episode context into the next
  episode without cross-role or hidden-state leakage;
- memory references trace-backed facts only;
- negative tests prove no hidden/scorer/cross-role memory leakage;
- replay does not require SDK session state;
- run reports include the required capability-curve ledger fields from
  `docs/capability-curve-contract.md`;
- served context is recorded by role and increased beyond the 32K smoke default
  before any run is treated as long-horizon capability evidence.

Required live verification:

- run bounded live campaign through local vLLM endpoints where feasible;
- inspect whether continuity changes behavior without hidden-state leakage.

Required tests:

- role-isolated sessions;
- hidden-state memory rejection;
- cross-role memory rejection;
- replay without SDK state;
- trace/session correlation metadata;
- served-context reporting;
- campaign-state handoff across episodes.

Stop conditions:

- custom session/memory/compaction primitives are introduced instead of using
  OpenAI Agents SDK where possible;
- SDK traces become environment truth;
- campaign replay depends on live SDK/session state;
- long-horizon runs use 32K smoke context but are presented as representative
  campaign or capability-curve evidence.

Review questions:

- Is Badlands JSONL still canonical?
- Are SDK sessions isolated per role?
- Does memory contain only role-visible evidence?
- Are within-run and across-episode adaptation separately visible in trace and
  qualitative model-output review?
- Are model, endpoint, scaffold, memory, tool surface, scenario, token budget,
  wall-clock budget, cost/power class, and served context recorded well enough
  for future comparisons?

## DS-25: realism provenance report and literature crosswalk

Linear: https://linear.app/mach-10/issue/DS-25/p2-add-realism-provenance-report-and-literature-crosswalk

Why now: execute near the end of the environment lane or in parallel only when
implementation is stable enough to map claims to artifacts.

Unlocks: credible research claims and reviewer visibility into implemented
evidence versus assumptions.

Must not pull forward: new simulator behavior or a full literature refresh.

Success criteria:

- every major environment mechanism is classified as implemented, partial,
  planned, or assumption;
- every realism claim has a source, local artifact, or validation plan;
- report is short enough to use.

Required verification:

- check cited paths and URLs exist;
- ensure public-facing claims are source-backed.

Stop conditions:

- provenance report becomes a literature dump;
- unsupported claims are phrased as validated.

## DS-26: sim-to-emulation calibration hooks

Linear: https://linear.app/mach-10/issue/DS-26/p2-prepare-sim-to-emulation-calibration-hooks-for-selected-actions

Why now: execute after or alongside DS-25 when major action semantics are stable.

Unlocks: future bridge from simulated worlds to emulated systems, real logs,
real software, and real operational constraints.

Must not pull forward: real CALDERA operations, unsafe exploit execution, or a
full emulator bridge.

Success criteria:

- calibration schema exists for source, action, preconditions, artifacts,
  duration range, success/failure notes, and confidence;
- at least three existing actions reference calibration records;
- missing calibration is explicit in reports;
- docs distinguish calibrated, heuristic, and unvalidated behavior.

Required verification:

- inspect that hooks improve auditability rather than fake precision;
- verify safety boundaries remain explicit.

Stop conditions:

- heuristic behavior is claimed as validated;
- calibration requires unsafe execution.
