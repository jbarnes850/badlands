# Badlands

Badlands is an always-on cyber self-play environment substrate. It is not another toy cyber benchmark; its first job is to prove that cyber self-play is meaningful only when the world being played in is valid.

## Core problem

Before cyber self-play can be useful, we need to prove that the world being played in is valid.

Mission owners need continuous, affordable, mission-realistic cyber self-play measurement: always-on environments where co-evolving attacker and defender agents stress-test mission systems under realistic operational constraints, so leaders can see how cyber risk changes as model capability, test-time compute, cost, and system state evolve.

## Environment-track first proof target

The first Badlands milestone is **construct-valid measurement**, not a large open world and not inference optimization. The minimum environment must preserve the causal pattern of a real mission network:

- attacker progress depends on persistence, credentials, lateral movement, noise, and timing;
- defender uncertainty depends on logs, alerts, EDR-like telemetry, tickets, identity events, and delayed/noisy detections rather than simulator truth;
- green/user activity creates the mission value to protect and the false-positive background that makes defense hard;
- actions have duration, delayed effects, and overlap;
- scoring penalizes both compromise and harmful defense, including false positives and mission disruption.

The first concrete world is the **Mission Desk enclave**: a small enterprise mission cell with an identity provider, file share, operator workstations, a mission application, email/ticket workflow, and SIEM/EDR-style telemetry. See `docs/minimum-valid-environment.md`.

## Design spine

Badlands uses the taxonomy from *Building Better Environments for Autonomous Cyber Defence* (arXiv:2604.08805v1):

- **Virtualisation gap**: whether network/host, user, and threat simulation reflect real dynamics.
- **Modelling gap**: whether observations, actions, rewards, and time preserve the real decision problem.

The NCSC frontier-AI defender guidance reinforces the operational reason for this substrate: AI changes attacker cost, speed, scale, and test-time compute; defenders keep an advantage only if they can shape their environment, maintain high-quality telemetry, and respond without creating worse operational harm.

## Run

Install dev dependencies and run checks with `uv`:

```bash
uv sync --extra dev
uv run --extra dev ruff check badlands tests
uv run --extra dev python -m pytest -q
uv run --extra dev python -m pytest -q tests/test_llm_actors.py
```

Start the contained local mission service:

```bash
docker compose -f infra/docker-compose.yml up --build
# health: curl http://localhost:18080/health
```

Run a seeded Mission Desk episode and replay scoring:

```bash
uv run badlands-episode --seed 7 --defender evidence_gathering --trace runs/mission-desk.jsonl
uv run badlands-replay runs/mission-desk.jsonl

# Optional scenario override
uv run badlands-episode --scenario badlands/scenarios/mission_desk.json --trace runs/mission-desk.jsonl

# Optional cached/live actor path
uv run badlands-episode --green-actor llm --attacker-actor llm --defender-actor llm --trace runs/mission-desk-llm.jsonl
```

Without installing scripts:

```bash
python3 -m badlands.cli --seed 7 --trace runs/mission-desk.jsonl
python3 -m badlands.scoring.replay runs/mission-desk.jsonl
```

## Initial artifacts

- `docs/autonomy-contract.md` — canonical mission charter, invariants, stop/go gates, and planner/executor/reviewer protocols for autonomous issue execution.
- `docs/execution-roadmap.md` — ordered remaining issue lane with per-issue contracts, validation expectations, deferred scope, and review questions.
- `docs/overnight-runbook.md` — one-issue-at-a-time autonomous execution loop with Linear/session-history intake, live validation, run ledger, subagent review, commit, and continuation gates.
- `docs/validation-matrix.md` — stable validation requirements by change type.
- `docs/capability-curve-contract.md` — co-evolution definition, run tiers, comparison axes, required metadata, and served-context rules for long-horizon measurement.
- `docs/run-ledger.md` and `docs/run-ledger.schema.json` — machine-readable run ledger contract for live, ablation, and long-horizon evidence.
- `docs/decisions.md` — architectural decision log for scope and layering decisions.
- `docs/architecture.md` — four-component architecture: attacker, defender, green/user simulator, and active network environment.
- `docs/environment-contract.md` — precise hidden state, observation surfaces, action surfaces, event model, timing model, and trace/scoring requirements.
- `docs/minimum-valid-environment.md` — narrative environment contract for the smallest plausible mission world.
- `docs/substrate-review.md` — citation-grade substrate table with realism anchors, gaps, and intended Badlands use.
- `docs/validity-experiments.md` — ablation matrix with expected directional outcomes and pass/fail criteria.
- `docs/validation-checklist.md` — reviewer checklist derived from the virtualisation/modelling-gap framework.
- `docs/implementation.md` — implemented vertical-slice architecture and realism-anchor mapping.
- `docs/trace-schema.md` — JSONL trace schema summary.
- `docs/reviewer-status.md` — satisfied and intentionally deferred contract items.
- `docs/dataset-fixtures.md` — LANL-derived auth-affinity fixture provenance.
- `docs/identity-service-contract.md` — identity provider service contract for authoritative auth/session/reset/credential state.
- `docs/scenario-fixtures.md` — scenario schema, provenance rules, and arXiv/NCSC taxonomy mapping for fixture-driven worlds.
- `docs/dgx-spark-live-inference.md` — opt-in Spark/vLLM live actor verification instructions, including current per-role attacker/defender/green endpoints.
