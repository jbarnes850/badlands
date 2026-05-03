# Overnight Runbook

This runbook defines the autonomous overnight workflow for Badlands issue
execution. It is intentionally strict: do not bend or lower the quality bar to
keep moving.

## Macro goal

Mission owners need continuous, affordable, mission-realistic cyber self-play
measurement: always-on environments where co-evolving attacker and defender
agents stress-test mission systems under realistic operational constraints, so
leaders can see how cyber risk changes as model capability, test-time compute,
cost, and system state evolve.

Every overnight execution should serve this goal. If a change makes Badlands a
cleaner toy benchmark but not a better mission-realistic measurement substrate,
stop and reconsider.

## Operating loop

For each issue, execute this loop:

1. Read the Linear issue in full.
2. Read canonical repo context:
   - `README.md`
   - `docs/autonomy-contract.md`
   - `docs/execution-roadmap.md`
   - `docs/validation-matrix.md`
   - `docs/capability-curve-contract.md`
   - issue-specific docs named by Linear.
3. Search historical Codex session logs for relevant prior context before
   repeating architecture work.
4. Produce a scoped plan:
   - issue id and goal;
   - likely files touched;
   - implementation boundaries;
   - explicit out-of-scope items;
   - test plan;
   - live validation plan;
   - expected trace/report/ledger artifacts;
   - stop conditions.
5. Execute the scoped plan.
6. Run full verification:
   - targeted tests;
   - baseline lint and pytest;
   - seeded trace and replay when runtime behavior changes;
   - DS-24 live inference validation for environment, observation, prompt,
     action, scoring, campaign, or qualitative-behavior changes.
7. Inspect live outputs qualitatively:
   - attacker objective progression and evidence use;
   - defender uncertainty handling, evidence gathering, and blast-radius
     reasoning;
   - green/user mission realism;
   - invalid, brittle, repeated, or hidden-state behavior.
8. Run a subagent-driven review pass to reduce executor bias.
9. Fix blocking findings and repeat verification.
10. Append meaningful acceptance, live, campaign, ablation, or blocker runs to
    `runs/run-ledger.jsonl` using `docs/run-ledger.schema.json`.
11. Commit in logical chunks.
12. Update Linear with:
    - commits;
    - validation commands and results;
    - live command and result;
    - trace/report/cache paths;
    - qualitative output summary;
    - residual risks;
    - reviewer status.
13. Move to the next issue only if the current issue reaches the quality bar and
    no stop condition fired.

## Historical session context

Before implementation, search repo-local history if available. Otherwise search
the global Codex history store:

```bash
sqlite3 /Users/jarrodbarnes/.codex/session-history/codex_sessions.sqlite \
  "SELECT m.timestamp, m.session_id, m.role, snippet(messages_fts, 0, '[', ']', '...', 16), m.source_path, m.line_no
   FROM messages_fts
   JOIN messages m ON m.id = messages_fts.rowid
   WHERE messages_fts MATCH '<issue id or concept>'
   ORDER BY bm25(messages_fts)
   LIMIT 20;"
```

Use history as context, not truth. Validate implementation claims against
Linear, repo docs, tests, traces, reports, and primary sources.

## Subagent protocol

Use subagents only where they materially reduce bias or run work in parallel.
Do not delegate the immediate blocking task.

Minimum useful subagent roles:

- Planner: validates scope, likely files, risk areas, tests, and live validation
  before implementation.
- Reviewer: findings-first review after implementation, with P1/P2/P3 issues,
  file/line references, validation review, and acceptance status.
- Explorer: answers narrow codebase questions when the executor needs context
  without broad speculation.

The executor remains responsible for integration, validation, final artifacts,
and not accepting weak review.

## Live verification requirement

For this lane, live inference is not decorative. It is part of the measurement
loop.

Any issue that changes environment behavior, observations, prompts, action
surfaces, scoring, mission workflows, campaign state, memory, or qualitative
review must end with:

- DS-24 `badlands-live-validate` or successor live command;
- endpoint preflight;
- completed trace with `score_snapshot`;
- replay success;
- compact report;
- cache path;
- per-role token/latency/attempt/repair/invalid telemetry;
- serving/backpressure evidence or explicit unavailable marker;
- qualitative attacker/defender/green output inspection;
- run-ledger entry.

Endpoint saturation is an infrastructure blocker, not an environment failure,
but it must be recorded with the exact endpoint, command, and follow-up command.

## Quality bar

Do not lower the bar to make progress.

An issue is not complete unless:

- acceptance criteria pass;
- lint and tests pass;
- replay is deterministic;
- score fields cite trace evidence;
- observations remain role-valid;
- hidden state is absent from role observations and memory;
- live model behavior is inspected qualitatively where applicable;
- invalid/brittle behavior is preserved as measurement signal;
- reviewer blocking findings are resolved;
- run artifacts are named and ledgered;
- Linear is updated with enough evidence for a human to audit later.

## Stop conditions

Stop instead of improvising when:

- a score cannot be recomputed from trace evidence;
- a live run cannot produce `score_snapshot` and replay;
- hidden/scorer/future state is needed for a role to succeed;
- implementation would pull DS-29 memory/session scope into earlier issues;
- arbitrary host tools or unsafe offensive capability would be required;
- the same fix fails twice;
- an advertised ablation is unimplemented;
- live output inspection shows the environment is being solved by a toy cue;
- capability-curve metadata is missing for a claimed comparison;
- the executor cannot produce a reviewer-ready artifact trail.

## Overnight approval authority

Jarrod is expected to be offline during an overnight run. The independent
reviewer/subagent is the approval authority for normal issue-by-issue
progression.

Allowed outcomes:

- `APPROVED`: executor may commit, update Linear, close/mark done, and continue
  to the next roadmap issue if all other gates are clean.
- `NOT APPROVED`: executor must fix within the current issue scope, rerun the
  relevant validation, and request another reviewer pass.
- `BLOCKED`: executor must stop, preserve artifacts, update Linear with blocker
  evidence, and wait for Jarrod.

The reviewer cannot waive live validation, approve scope expansion, weaken
trace/replay canonicality, allow hidden-state leakage, or pull DS-29 memory and
campaign work into earlier issues. Those require Jarrod, so the correct
overnight action is to stop.

## Current autonomous lane

Follow the lane in `docs/execution-roadmap.md`:

```text
DS-20 -> DS-21 -> DS-22 -> DS-28 -> DS-27 -> DS-23 -> DS-29 -> DS-25/DS-26
```

Execute one issue at a time. The first overnight run should prefer `DS-20`
only, or at most continue to `DS-21` if `DS-20` is fully verified and approved
by the reviewer protocol.
