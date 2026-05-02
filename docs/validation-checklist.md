# Badlands Environment Validation Checklist

Derived from the virtualisation/modelling-gap taxonomy in arXiv:2604.08805v1 and the operational concerns in the NCSC frontier-AI defender guidance.

## Virtualisation gap

- [ ] Network and host roles are tied to a named mission workflow, not arbitrary nodes.
- [ ] Host/service behavior includes operational characteristics: availability, latency/failure, user ownership, criticality, and dependencies.
- [ ] Green users generate normal work, auth, files, email/tickets, and benign noise.
- [ ] Green disruption changes mission score.
- [ ] Red behavior is calibrated against adversary emulation or ATT&CK-mapped traces.
- [ ] Red is not fully deterministic across episodes.
- [ ] Sensor coverage, logging delay, dropped events, and detection noise are explicit.
- [ ] A higher-fidelity replay/emulation path is identified for at least one attack chain.

## Modelling gap: sequence/time

- [ ] The environment clock is event-driven or explicitly maps steps to wall-clock time.
- [ ] Actions have duration and delayed effects.
- [ ] Attacker, defender, and green processes can overlap.
- [ ] Race conditions affect outcome.
- [ ] Episode length and discount/score windows have mission meaning.

## Modelling gap: observations

- [ ] No defender observation exposes hidden simulator truth.
- [ ] Defender observations are logs, alerts, EDR-like telemetry, auth/network events, tickets, inventory, and delayed action results.
- [ ] Alerts include source events and rule/provenance metadata.
- [ ] Observations include false positives and incomplete evidence.
- [ ] Attacker observations are limited to command/tool outputs and accessible resources.

## Modelling gap: actions

- [ ] Every action maps to a real defender/attacker capability.
- [ ] Each action specifies prerequisites, duration, success/failure modes, side effects, and observable artifacts.
- [ ] Defensive containment has blast radius and rollback mechanics.
- [ ] Actions can fail or be partially effective.

## Modelling gap: reward/scoring

- [ ] Scoring is separate from agent observations.
- [ ] Scoring is auditable from the trace.
- [ ] Security score penalizes dwell, persistence, credential spread, lateral reach, objective completion, and exfiltration/disruption.
- [ ] Mission score penalizes downtime, user lockouts, missed tasks, ticket backlog, and blocked dependencies.
- [ ] Defensive quality score rewards timely, evidence-based, least-disruptive containment.
- [ ] Security-only shutdown policies fail.

## Required ablations before claiming validity

- [ ] No-persistence ablation.
- [ ] Magic-observation ablation.
- [ ] No-green ablation.
- [ ] Instant-action/turn-based ablation.
- [ ] No-noise/no-false-positive ablation.
- [ ] Security-only scoring ablation.

## Reviewer red flags

- [ ] The fastest winning defender policy is “isolate everything.”
- [ ] A classifier can solve the environment from alert labels alone.
- [ ] Removing users does not change optimal defense.
- [ ] Delays and concurrency do not change outcomes.
- [ ] Scores cannot be recomputed from recorded traces.
- [ ] Claims of realism lack a cited dataset, platform, workflow, or higher-fidelity validation plan.
