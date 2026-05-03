# Implementation Notes

This vertical slice implements the Mission Desk enclave contract as a small active-network runtime plus event-sourced environment core.

## Runtime pieces

- `badlands.core.env.MissionDeskEnv`: event-driven active network world. Owns hidden host, identity, mission, telemetry, attacker, and defender state.
- `badlands.core.defender_actions`: centralized defender action surface and durations shared by the environment, CLI, live harness, and LLM allowlist.
- `badlands.core.trace.TraceWriter`: append-only JSONL trace with JSON-schema validation.
- `badlands.core.observations`: separate attacker/defender/green views and forbidden-field leak guard.
- `badlands.agents.baselines`: do-nothing, isolate-everything, alert-label, evidence-gathering, and random defenders.
- `badlands.scoring.replay`: derives all scores from trace events only.
- `badlands.network.mission_app`: local contained HTTP mission service used by Docker Compose as the first real service surface.
- `infra/docker-compose.yml`: isolated local mission app network.
- `badlands/scenarios/mission_desk.json`: scenario-defined benign noise and
  sensor profile for DS-20 uncertainty and observation ablations.

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

## Intentional limits

The Docker Compose service is the first local service anchor, but the Python environment core currently drives most episode state directly for deterministic tests. This avoids premature distributed complexity while preserving trace/event/observation/scoring contracts. DS-20 noise/sensor rates are heuristic and scenario-documented; DS-25/DS-26 own stronger provenance and calibration. Next validation step: wire green actions and attacker/defender actions through the HTTP service and container logs for a larger fraction of telemetry.
