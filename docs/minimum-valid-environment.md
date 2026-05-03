# Minimum Valid Environment: Mission Desk Enclave

## 1. What is the minimum valid mission world?

A two-hour simulated mission window for a small enterprise mission cell. Ten to twenty users operate workstations against a mission web app, shared file store, email, ticket queue, identity provider, and logging stack. One attacker starts from a phished user workstation or stolen credential. One defender operates from SIEM/EDR/ticket views and can investigate, contain, reset accounts, block indicators, restore service, and escalate.

The world is intentionally small, but it must include stateful attacker persistence, defender uncertainty, green activity, concurrent timing, and mission-impact scoring.

## 2. Real-world workflow represented

A SOC/mission-defense workflow for an enterprise enclave during a suspected intrusion: alerts arrive, analysts triage, inspect endpoint/process/auth/network evidence, choose containment or monitoring, coordinate with users/tickets, and balance incident response against mission continuity.

## 3. Realism anchors

- arXiv:2604.08805v1: virtualisation gap and modelling gap; explicit need for realistic green/red agents, observations grounded in practical monitoring, asynchronous sequence modelling, and reward alignment with security plus normal operations.
- NCSC, “Why cyber defenders need to be ready for frontier AI”: frontier AI lowers attack cost and increases speed/scale; current attacker-agent activity is often detectable only where monitoring and response are effective; automated mitigation risks service disruption exceeding attack impact; defender advantage comes from shaping the environment and maintaining high-quality data.
- DARPA OpTC: endpoint telemetry at enterprise scale, useful for process/file/network event schemas and benign/adversarial background rates.
- LANL enterprise event datasets: authentication, process/network/DNS/flow-style temporal patterns for green behavior and identity graph structure.
- Mordor / OTRF Security Datasets: ATT&CK-mapped adversarial traces for replayable detection workflows.
- MITRE CALDERA: adversary emulation action calibration.
- Elastic ECS / detection-rules and Sigma: production-style event normalization and alert logic.

## 4. State variables

Simulator state is hidden from agents and separated from scoring evidence.

- Assets: host role, OS/service inventory, criticality, owner, patch posture, network segment.
- Identity: users, groups, privileges, sessions, credentials, MFA/reset state.
- Mission: task queue, file availability, app health, user productivity, deadlines.
- Attacker: foothold, credentials known, persistence mechanisms, lateral position, objectives achieved, noise generated.
- Defender: open alerts, cases, evidence gathered, pending actions, action cooldowns, analyst time budget.
- Telemetry: event buffers, detection delays, sensor coverage, dropped/noisy events.
- Time: continuous/event-driven clock; every process schedules start, duration, completion, and side effects.

## 5. Processes

### Attacker/red

Initial access via phished workstation or valid credential; discovery; credential access; persistence; lateral movement; collection/exfiltration or mission app disruption. Actions produce artifacts rather than direct labels.

### Defender/blue

Alert triage, hypothesis-driven investigation, host/user/network lookup, containment, credential reset, block rule, process kill, host isolation, restore, escalation, rollback. Defender must decide under uncertainty and limited analyst/action budget.

### User/green

Users log in, access files, send emails, create tickets, run benign admin scripts, trigger occasional noisy-but-benign alerts, and require the mission app. Green behavior creates both protected value and false-positive background.

## 6. Observations

No agent receives `host_compromised=true`, attacker location, ground-truth intent, or hidden simulator state.

- Defender sees: SIEM alerts, normalized ECS-like events, EDR process trees, auth events, DNS/network summaries, email/ticket text, asset inventory, case notes, and action results after delay.
- Attacker sees: command output, accessible files, network/service discovery results, credential material actually obtained, error messages, and timing delays.
- Green sees: application success/failure, account lockouts, host isolation disruption, ticket responses.

## 7. Actions and durations

Representative durations are part of the environment contract and should be calibrated from datasets/emulation where possible.

- Defender investigate alert: 2-6 min; yields linked events with possible noise.
- Query endpoint/auth/network history: 1-4 min; delayed by logging latency.
- Isolate host: 1-3 min to apply; immediately harms user productivity if false/overbroad.
- Reset account/revoke token: 2-5 min; can disrupt active mission work.
- Block domain/IP/hash: 1-5 min; may block benign dependencies.
- Restore host/service: 5-20 min.
- Attacker discovery: 1-5 min; noisy auth/process/network events.
- Credential access: 3-15 min; may trigger EDR/auth anomalies.
- Lateral movement: 2-10 min; success depends on creds, network path, defense timing.
- Collection/exfiltration/disruption: 5-30 min; mission impact accumulates.

Actions overlap. The defender may isolate a host while attacker lateral movement is in flight and users continue generating background activity.

## 8. Scoring axes

Scoring is computed from the trace, not privileged labels exposed to agents.

- Mission continuity: completed green tasks, app/file availability, deadline misses.
- Security outcome: attacker dwell time, persistence survival, credential spread, lateral reach, objective completion, exfiltration/disruption.
- Defensive quality: true-positive containment, time-to-detect, time-to-contain, evidence sufficiency, least-disruptive response.
- Harmful defense: false positive isolations, unnecessary resets, blocked mission dependencies, unresolved tickets, excessive analyst cost.
- Cost: action count, analyst minutes, compute/replay cost for always-on use.

## 9. Ablations that prove realism dimensions matter

1. Remove persistence: attacker footholds disappear between steps. A valid defender policy should become artificially easier; if scores do not change, persistence is not represented.
2. Give an experiment-only oracle baseline compromise truth outside the
   production defender observation path. Scores should inflate; if not,
   observation uncertainty is ineffective.
3. Remove green activity: host isolation has no cost. Aggressive containment should become over-rewarded; the full environment must penalize it.
4. Make time turn-based/instant: no overlap or delayed effects. Race conditions and preemption should disappear.
5. Remove false positives/noisy benign alerts: triage becomes a label-reading task.
6. Security-only reward: ignore mission continuity. Defender should learn shutdown policies; full scoring must reject them.

## 10. Invalid/toy-like failure modes

- Defender observes ground truth or simulator-only vectors.
- Alerts are deterministic labels rather than noisy artifacts.
- No benign users, no mission value, or no penalty for disruption.
- Instantaneous actions in a synchronous game loop without justified wall-clock semantics.
- Reward directly reads hidden compromise state without auditable trace evidence.
- Red behavior is scripted, predictable, and not calibrated against emulation/traces.
- The environment cannot replay a run into logs, actions, mission impact, and score.
