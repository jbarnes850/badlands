# Badlands

Badlands is a local cyber self-play substrate for mission-realistic,
long-horizon agent evaluation.

It measures how mission risk changes when attacker, defender, and mission-user
agents interact inside the same stateful environment under role-valid
observations, fixed operational constraints, and replayable evidence.

Badlands is not a benchmark leaderboard and not an offensive tool suite. It is a
contained research environment for studying autonomous cyber decision making,
co-evolution, and capability curves under mission constraints.

![Badlands self-play environment loop](assets/badlands-system-loop.png)

## Environment Loop

The current release contains a small but complete mission world where attacker
and defender agents co-evolve through role-visible feedback while green/user
activity keeps mission work alive. Within an
episode, agents respond to the evolving environment state. Across episodes,
role-isolated campaign memory carries forward trace-linked lessons without
sharing hidden labels, scorer truth, or cross-role state.

Badlands includes:

- an identity provider, mission application, file share, tickets, workstations,
  dependency graph, and telemetry;
- green mission-user activity that keeps normal work alive;
- bounded attacker and defender action surfaces;
- role-isolated observations for attacker, defender, and green/user agents;
- canonical JSONL traces for every environment event;
- replay scoring from trace evidence only;
- campaign memory with role-isolated namespaces;
- token, latency, invalid-decision, repair, replay, and endpoint accounting;
- a read-only operator dashboard for live campaign inspection.

The default scenario is `badlands/scenarios/mission_desk.json`.

## What We Measure

Badlands makes cyber self-play measurable by tying every score and headline state
back to JSONL evidence. The useful claim is not that an agent can attack. The
useful claim is that a mission owner can repeatedly measure how attacker progress,
defender quality, mission disruption, token spend, wall-clock time, and campaign
memory evolve under fixed mission constraints.
```

## Getting Started

Badlands uses Python 3.11+ and `uv`.

```bash
uv sync --extra dev
uv run --extra dev ruff check badlands tests
uv run --extra dev python -m pytest -q
```

## First Run: No Model Server

This path does not require model serving.

```bash
uv run badlands-episode \
  --seed 7 \
  --defender evidence_gathering \
  --trace runs/mission-desk.jsonl

uv run badlands-replay runs/mission-desk.jsonl
```

Useful ablations:

```bash
uv run badlands-episode --seed 7 --no-green --trace runs/no-green.jsonl
uv run badlands-episode --seed 7 --perfect-sensors --trace runs/perfect-sensors.jsonl
uv run badlands-validity --out runs/validity
```

## Bring Your Own Models

Badlands expects OpenAI-compatible local chat-completion endpoints. vLLM is the
primary serving target, but the runner is configured by endpoint URL and model
name rather than by provider.

The generic variables apply to all roles:

```bash
export BADLANDS_LLM_BASE_URL=http://127.0.0.1:8000/v1
export BADLANDS_LLM_MODEL=local-model-name
export BADLANDS_LLM_API_KEY=EMPTY
export BADLANDS_LLM_ENABLE_THINKING=false
```

Role-specific variables override the generic values:

```bash
export BADLANDS_ATTACKER_LLM_BASE_URL=http://127.0.0.1:18000/v1
export BADLANDS_ATTACKER_LLM_MODEL=attacker-local-model
export BADLANDS_DEFENDER_LLM_BASE_URL=http://127.0.0.1:18001/v1
export BADLANDS_DEFENDER_LLM_MODEL=defender-local-model
export BADLANDS_GREEN_LLM_BASE_URL=http://127.0.0.1:18001/v1
export BADLANDS_GREEN_LLM_MODEL=green-local-model
```

Using the same endpoint for defender and green/user simulation is allowed. Using
the same memory, session, cache key, actor identity, trace role, or telemetry
bucket is not.

For vLLM, Badlands sends structured JSON response formats and
`chat_template_kwargs={"enable_thinking": false}`. The preflight fails if the
endpoint returns reasoning content instead of JSON `message.content`.

## Run One Live Episode

```bash
uv run badlands-live-validate \
  --seed 7000 \
  --until 40 \
  --trace runs/live-validation.jsonl \
  --report runs/live-validation-report.json \
  --cache runs/live-validation-cache \
  --attacker-model "$BADLANDS_ATTACKER_LLM_MODEL" \
  --defender-model "$BADLANDS_DEFENDER_LLM_MODEL" \
  --green-model "$BADLANDS_GREEN_LLM_MODEL"
```

Then replay the trace:

```bash
uv run badlands-replay runs/live-validation.jsonl
```

## Long-Horizon Runs

The campaign runner repeats episodes until the wall-clock budget expires or a
hard stop condition fires. It preserves one trace per episode, replays each
completed trace, extracts role-visible memory, and maintains dashboard-readable
state.

```bash
RUN_ID="262k-campaign-memory-6h-$(date +%Y%m%d-%H%M)"

uv run badlands-campaign-run \
  --duration-minutes 360 \
  --episode-until 40 \
  --seed-start 7000 \
  --out "runs/${RUN_ID}" \
  --sdk-mode direct \
  --memory-mode sdk_raw_trajectory \
  --sdk-session-item-limit none \
  --served-context-target 262144
```

For a short local rehearsal:

```bash
uv run badlands-campaign-run \
  --duration-minutes 0 \
  --min-episodes 1 \
  --max-episodes 1 \
  --episode-until 20 \
  --seed-start 7000 \
  --out runs/rehearsal \
  --sdk-mode direct \
  --memory-mode sdk_raw_trajectory \
  --sdk-session-item-limit none \
  --served-context-target 262144
```

## Dashboard

The dashboard is static and read-only. For second-by-second token and action
updates during long model calls, run the live-state sidecar next to the campaign:

```bash
uv run badlands-campaign-live-state \
  --run-dir "runs/${RUN_ID}" \
  --interval-seconds 1
```

This writes `operator-live-state.json` from the latest `operator-state.json`,
in-progress traces, and `agents-sdk-sessions.sqlite`. Replay status and final
scores still update only after completed episodes because they require a
completed trace.

From the repository root:

```bash
uv run --extra dev python -m http.server 8765 --bind 127.0.0.1
```

Open:

```text
http://127.0.0.1:8765/operator-ui/?state=/runs/<campaign-id>/operator-live-state.json
```

## Boundaries

Badlands is a contained local cyber range. It does not provide arbitrary shell
access, external targeting, agent-authored exploit tooling, model fine-tuning, or
prompt/scaffold self-improvement. The action surfaces are bounded environment
actions whose effects are recorded in JSONL.

The current release is an environment and measurement substrate. It is not a
claim that the default agents are strong, that the scenario is exhaustive, or
that results transfer without calibration. The intended research use is to run
controlled campaigns, inspect trace evidence, and compare capability curves under
fixed scenario, model, scaffold, memory, and compute settings.

## References

- Chris Hicks et al. "Building Better Environments for Autonomous Cyber Defence."
  arXiv:2604.08805v1, 2026. https://arxiv.org/pdf/2604.08805v1
- Paul J. and Alan Steer. "Why cyber defenders need to be ready for frontier
  AI." National Cyber Security Centre, 2026.
  https://www.ncsc.gov.uk/blogs/why-cyber-defenders-need-to-be-ready-for-frontier-ai
