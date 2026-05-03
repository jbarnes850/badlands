# Mission Service Contract

DS-17 made mission app, file-share, and ticket outcomes authoritative in the
local HTTP service. DS-28 extends that boundary from a hardcoded demo task into
scenario-defined mission workflows. Python schedules green tasks and mirrors
service-observed outcomes into trace events, but it does not decide mission
completion, file access, deadline misses, degraded-mode latency, or ticket
creation without service telemetry evidence.

## Authority Boundary

- `POST /mission/task`: records mission task success or failure in service state and emits a `mission_task` service event. The service resolves `task_id` against `mission.workflow_tasks`, enforces required role/services/files, applies service-specific degraded-mode latency or failure, and records deadline outcomes.
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

DS-28 service profiles define how degraded dependencies affect mission work.
The default scenario treats degraded `mission_app` as latency-bearing so
deadlines can be missed without total outage. Degraded file-share, ticket, and
IdP services still fail the affected task because those workflows cannot
complete safely without the backing service.

## Workflow Tasks

Scenario workflow tasks are the contract between mission realism and the active
service. Each task has:

- `task_id`, `workflow_id`, `task_type`, and optional `requested_action`.
- `scheduled_at`, `deadline_at`, and `priority`.
- `required_role`, `required_services`, and `required_files`.
- `success_outcome` and `failure_outcome` strings recorded by the service.

The default fixture includes `use_mission_app`, `read_write_file`,
`submit_report`, and `retry_after_failure` tasks across `mission_analyst` and
`mission_coordinator` roles. `mission.green_task_schedule` is derived from
`workflow_tasks[].scheduled_at` when workflow tasks are present.

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
- `badlands.workflow.id`, `badlands.task.type`, `badlands.task.priority`
- `badlands.task.deadline_at`, `badlands.task.completed_at`
- `badlands.latency.minutes`, `badlands.degraded`, and `badlands.degraded.services`
- `badlands.required.role`, `badlands.user.role`, and `badlands.ticket.status`

The environment ingests these records as `telemetry_emitted` events with
`category=service` or `category=auth`. `mission_task_event` records cite the
service/auth telemetry in `source_event_ids` and as trace parents. Replay
scoring derives mission completion/failure, deadline minutes lost, and ticket
backlog from trace evidence, while reviewer evidence can follow the parent
links back to service logs.

## Observation Boundary

Green observations do not expose hidden app, file, ticket, dependency, or IdP
truth before the user acts. Green users see assigned task context, role,
deadline, priority, prior user-experienced outcomes, tickets, and app
responses. Defender observations see tickets through role-valid service
telemetry and mission/ticket trace artifacts, not through hidden service state.

## Source Grounding

NCSC frontier-AI guidance motivates comprehensive logging, robust access controls, mission continuity, and caution around automated response that can disrupt operations. DS-17 implements those concerns by making green mission harm depend on active service outcomes and by preserving harmful-defense evidence for lockout/isolation effects.

The arXiv 2604.08805 environment taxonomy frames this slice as reducing both the virtualisation gap and modelling gap: mission work is no longer a symbolic counter alone, and action/reward evidence is tied to service state and observations. NIST SP 800-61 Rev. 2 and the CISA playbook motivate ticketed, evidence-backed incident-response workflows. Elastic Common Schema motivates the normalized service/auth fields used for trace-visible telemetry.

## Deferred Work

- DS-23: validity runner and systematic ablation reports are deferred.
- DS-24: live inference harness is available but remains a smoke harness until DS-29 adds long-horizon actor sessions.
- DS-25/DS-26: workflow rates, degraded-mode probabilities, and task durations are still heuristic until calibrated against source traces/workflows.
