# Mission Service Contract

DS-17 makes current mission app, file share, and ticket outcomes authoritative in the local HTTP service. Python schedules green tasks and mirrors service-observed outcomes into trace events, but it does not decide mission completion, file access, or ticket creation without service telemetry evidence.

## Authority Boundary

- `POST /mission/task`: records mission task success or failure in service state and emits a `mission_task` service event.
- `GET /file/<name>`: reads file-share content only after IdP session validation and emits `file_read` service telemetry.
- `POST /ticket`: creates a ticket in service state and emits `ticket_created` telemetry.
- `GET /tickets`: returns service-owned tickets for integration checks and future workflows.
- `POST /ticket/update`: updates service-owned ticket status and emits `ticket_updated` telemetry.

The service remains local and contained with the existing Mission Desk service process. IdP session validation is still owned by the identity service contract; file and mission endpoints call that IdP state rather than trusting Python mirrors.

DS-18 adds dependency-state enforcement to these endpoints. The dependency
graph controller pushes `available`, `degraded`, or `unavailable` state into
the service via `/admin/service_state`; mission, file, identity, and ticket
endpoints fail with dependency reasons when their service state cannot support
work.

## Telemetry

Mission service events use ECS-like fields where practical:

- `run_id`
- `@timestamp`
- `event.category`
- `event.action`
- `event.outcome`
- `event.reason`
- `user.name`
- `source.host`
- `destination.service`
- `service.name`
- `session.id` when an IdP session is involved
- `file.name`, `badlands.task.id`, or `badlands.ticket.id` for mission artifacts

The environment ingests these records as `telemetry_emitted` events with `category=service` or `category=auth`. `mission_task_event` records cite the service/auth telemetry in `source_event_ids` and as trace parents. Replay scoring continues to derive mission completion/failure from `mission_task_event`, while reviewer evidence can follow the parent links back to service logs.

## Observation Boundary

Green observations do not expose hidden app, file, ticket, or IdP truth before the user acts. Green users see task context and prior user-experienced outcomes. Defender observations see tickets through role-valid service telemetry and mission/ticket trace artifacts, not through hidden service state.

## Source Grounding

NCSC frontier-AI guidance motivates comprehensive logging, robust access controls, mission continuity, and caution around automated response that can disrupt operations. DS-17 implements those concerns by making green mission harm depend on active service outcomes and by preserving harmful-defense evidence for lockout/isolation effects.

The arXiv 2604.08805 environment taxonomy frames this slice as reducing both the virtualisation gap and modelling gap: mission work is no longer a symbolic counter alone, and action/reward evidence is tied to service state and observations. NIST SP 800-61 Rev. 2 and the CISA playbook motivate ticketed, evidence-backed incident-response workflows. Elastic Common Schema motivates the normalized service/auth fields used for trace-visible telemetry.

## Deferred Work

- DS-18: service dependencies are represented and mission tasks cite dependencies, but dependency graph outage propagation is still limited.
- DS-20: benign noise and sensor limits are not yet calibrated.
- DS-21: defender workflow remains compact; richer cases/escalation are deferred.
- DS-23: validity runner and systematic ablation reports are deferred.
- DS-24: inference harness improvements are deferred.
- DS-28: richer mission workflows, deadlines, and multi-step app semantics are deferred.
