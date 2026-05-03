# Badlands Environment Validation Checklist

Derived from the virtualisation/modelling-gap taxonomy in arXiv:2604.08805v1 and the operational concerns in the NCSC frontier-AI defender guidance.

## Virtualisation gap

- [x] Network and host roles are tied to a named mission workflow, not arbitrary nodes.
- [x] Host/service behavior includes operational characteristics: availability, degraded/unavailable failure states, user ownership, criticality, and dependencies.
- [x] Green users generate normal work, auth, files, tickets, and benign noise.
- [x] Green disruption changes mission score.
- [x] Red behavior carries per-action calibration status and explicit warnings.
- [ ] Red behavior is measured against adversary emulation or ATT&CK-mapped traces.
- [ ] Red is not fully deterministic across episodes.
- [x] Sensor coverage, logging delay, dropped events, and detection noise are explicit.
- [x] A higher-fidelity replay/emulation path is identified for selected attack and response actions.
- [ ] At least one selected action is calibrated against a reviewed replay/emulation artifact.

## Modelling gap: sequence/time

- [x] The environment clock is event-driven or explicitly maps steps to wall-clock time.
- [x] Actions have duration and delayed effects.
- [x] Attacker, defender, and green processes can overlap.
- [x] Race conditions affect outcome.
- [x] Episode length and discount/score windows have mission meaning.

## Modelling gap: observations

- [x] No defender observation exposes hidden simulator truth.
- [x] Defender observations are logs, alerts, EDR-like telemetry, auth/network events, tickets, inventory, and delayed action results.
- [x] Alerts include source events and rule/provenance metadata.
- [x] Observations include false positives and incomplete evidence.
- [ ] Attacker observations are limited to command/tool outputs and accessible resources.

## Modelling gap: actions

- [x] Every implemented defender action maps to a real defender capability.
- [x] Each implemented defender action specifies prerequisites, duration, success/failure modes, side effects, and observable artifacts.
- [x] Defensive containment has blast radius and rollback mechanics.
- [x] Defender actions can fail or be partially effective.

## Modelling gap: reward/scoring

- [x] Scoring is separate from agent observations.
- [x] Scoring is auditable from the trace.
- [x] Security score penalizes dwell, persistence, credential spread, lateral reach, objective completion, and exfiltration/disruption.
- [x] Mission score penalizes downtime, user lockouts, missed tasks, ticket backlog, and blocked dependencies.
- [x] Defensive quality score rewards trace-backed response and penalizes analyst time, false positives, and harmful disruption.
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

## Provenance gate

- [x] Reviewer-facing realism provenance crosswalk exists:
  [`docs/realism-provenance.md`](realism-provenance.md).
- [x] The crosswalk covers scenario, identity, mission services, green
  behavior, attacker actions, defender actions, observations, timing, scoring,
  ablations, live inference, campaign memory, and sim-to-emulation calibration
  hooks.
- [ ] Before external claims, every implemented-realism statement must cite the
  crosswalk row, local artifact, and source anchor it depends on.

## Calibration gate

- [x] Calibration records exist for selected scan, credential access, lateral
  movement, collection, isolate, reset, and restore actions.
- [x] Missing action calibration emits an explicit warning/report field.
- [x] Initial records distinguish `heuristic` from future `calibrated` status.
- [ ] Any claim of measured calibration cites a reviewable CALDERA, Mordor/OpTC,
  NASimEmu, Cyberwheel, or mission-owner evidence artifact.
