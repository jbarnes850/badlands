# Implementation Notes

This vertical slice implements the Mission Desk enclave contract as a small active-network runtime plus event-sourced environment core.

## Runtime pieces

- `badlands.core.env.MissionDeskEnv`: event-driven active network world. Owns hidden host, identity, mission, telemetry, attacker, and defender state.
- `badlands.core.attacker_actions`: centralized attacker action surface and
  durations shared by the environment, CLI, live harness, and LLM allowlist.
- `badlands.core.defender_actions`: centralized defender action surface and durations shared by the environment, CLI, live harness, and LLM allowlist.
- `badlands.core.trace.TraceWriter`: append-only JSONL trace with JSON-schema validation.
- `badlands.core.observations`: separate attacker/defender/green views and forbidden-field leak guard.
- `badlands.agents.baselines`: do-nothing, isolate-everything, alert-label, evidence-gathering, and random defenders.
- `badlands.scoring.replay`: derives all scores from trace events only.
- `badlands.network.mission_app`: local contained HTTP mission service used by Docker Compose as the first real service surface.
- `infra/docker-compose.yml`: isolated local mission app network.
- `badlands/scenarios/mission_desk.json`: scenario-defined benign noise and
  sensor profile for DS-20 uncertainty and observation ablations, plus DS-28
  workflow tasks, user roles, deadlines, service profiles, and user-facing
  outcomes.

## Realism anchor mapping

- arXiv 2604.08805 virtualisation gap: the active environment includes hosts, identity, services, green users, red actions, and telemetry rather than only symbolic labels.
- arXiv modelling gap: actions have durations; observations are artifacts; scores are trace-derived; attacker/defender/green processes overlap on an event clock.
- NCSC frontier-AI guidance: harmful automated response is scored through lockout/isolation harm and mission failure.
- ECS/Elastic/Sigma direction: telemetry payloads use ECS-like field names and alerts include rule id, severity, confidence, source event ids, and ATT&CK tags.
- CALDERA/Mordor/OpTC/LANL plan: current action artifacts and benign/noisy telemetry are deliberately small but shaped so later calibration can replace durations/rates with higher-fidelity traces.
- LANL/OpTC/NCSC DS-20 noise: failed-auth bursts, endpoint script noise,
  file-access bursts, service-health blips, and ticket spikes create
  mission-plausible false-positive pressure without hidden labels.
- Observation modelling: telemetry carries sensor coverage/drop/delay metadata;
  defender observations only expose covered, non-dropped, currently visible
  artifacts, while the JSONL trace remains canonical for replay.
- DS-21 defender workflow: triage/query/escalate/contain/restore/rollback
  actions map to NIST/CISA incident response phases. `triage_alert`,
  `query_endpoint`, `query_identity`, and `query_network` support detection,
  analysis, scoping, and evidence preservation. `isolate_host`,
  `reset_account`, `block_indicator`, and `kill_process` model containment and
  mitigation with explicit blast-radius risk. `restore_host_or_service` and
  `rollback` model recovery and reversal of harmful response. `escalate`
  models case coordination at analyst-time cost. `block_indicator` is aligned
  with OpenC2-style deny/block concepts, while `isolate_host`,
  `reset_account`, and `kill_process` correspond to common D3FEND/OpenC2
  containment and eviction concepts.
- DS-22 attacker objectives: `collect`, `exfiltrate`, and `disrupt_service`
  are explicit scenario objectives tied to protected assets and mission
  dependencies. Collection requires lateral position, credentialed access,
  non-isolated host state, and available file-share dependency. Exfiltration
  requires prior collection and emits contained network telemetry to
  `contained-sink.badlands.local`; it does not open a real egress path.
  Service disruption requires a plausible foothold and drives dependency,
  mission, and security score effects. Objective artifacts are ATT&CK-shaped
  and intended for later DS-25/DS-26 calibration against Mordor/OpTC/CALDERA
  traces.
- DS-28 mission workflow service: green work is scenario-driven rather than a
  hardcoded demo. The active service enforces task roles, required services,
  required files, deadlines, degraded-mode latency/failure, ticket creation,
  and workflow outcomes. Trace-ingested service telemetry records workflow id,
  task type, deadline/completion time, latency, degraded service ids, and role
  context; replay scores completed/failed tasks, deadline minutes lost, ticket
  backlog, and service downtime from evidence-bearing events. This maps to the
  NCSC focus on operational continuity under automated response pressure and to
  arXiv 2604.08805's modelling-gap requirement for realistic green agents,
  observations, and reward evidence.

## Intentional limits

The Docker Compose service is the first local service anchor, but the Python
environment core currently drives some episode state directly for deterministic
tests. This avoids premature distributed complexity while preserving
trace/event/observation/scoring contracts. DS-20 noise/sensor rates, DS-22
objective durations/artifact rates, and DS-28 workflow/service-profile timings
are heuristic and scenario-documented; DS-25/DS-26 own stronger provenance and
calibration. Next validation step: wire more attacker/defender host behavior
through service/container logs and calibrate workflow rates against mission
source packs.
