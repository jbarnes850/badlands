# Implementation Notes

This vertical slice implements the Mission Desk enclave contract as a small active-network runtime plus event-sourced environment core.

## Runtime pieces

- `badlands.core.env.MissionDeskEnv`: event-driven active network world. Owns hidden host, identity, mission, telemetry, attacker, and defender state.
- `badlands.core.trace.TraceWriter`: append-only JSONL trace with JSON-schema validation.
- `badlands.core.observations`: separate attacker/defender/green views and forbidden-field leak guard.
- `badlands.agents.baselines`: do-nothing, isolate-everything, alert-label, evidence-gathering, and random defenders.
- `badlands.scoring.replay`: derives all scores from trace events only.
- `badlands.network.mission_app`: local contained HTTP mission service used by Docker Compose as the first real service surface.
- `infra/docker-compose.yml`: isolated local mission app network.

## Realism anchor mapping

- arXiv 2604.08805 virtualisation gap: the active environment includes hosts, identity, services, green users, red actions, and telemetry rather than only symbolic labels.
- arXiv modelling gap: actions have durations; observations are artifacts; scores are trace-derived; attacker/defender/green processes overlap on an event clock.
- NCSC frontier-AI guidance: harmful automated response is scored through lockout/isolation harm and mission failure.
- ECS/Elastic/Sigma direction: telemetry payloads use ECS-like field names and alerts include rule id, severity, confidence, source event ids, and ATT&CK tags.
- CALDERA/Mordor/OpTC/LANL plan: current action artifacts are deliberately small but shaped so later calibration can replace durations/rates with higher-fidelity traces.

## Intentional limits

The Docker Compose service is the first local service anchor, but the Python environment core currently drives most episode state directly for deterministic tests. This avoids premature distributed complexity while preserving trace/event/observation/scoring contracts. Next validation step: wire green actions and attacker/defender actions through the HTTP service and container logs for a larger fraction of telemetry.
