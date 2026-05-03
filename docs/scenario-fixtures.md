# Scenario Fixtures

Badlands scenarios are inspectable realism contracts. They define the mission world being measured before agents act in it. The default fixture is `badlands/scenarios/mission_desk.json`.

## Schema

The current schema is intentionally small:

- `scenario_id`, `name`, `description`: reviewer-facing identity and mission narrative.
- `auth_affinity_dataset`: path to the LANL-derived user-host affinity fixture used for green identity cadence and host assignment.
- `hosts`: host inventory with `host_id`, `role`, `owner`, `criticality`, and optional initial file/process state.
- `users`: mission users with `user_id`, `primary_host`, optional `role`, and optional `credentials_exposed`.
- `services`: service inventory with `service_id`, `host_id`, `kind`, `criticality`, and optional `depends_on`.
- `mission`: task template, green task schedule, scenario workflow tasks, service profiles, and service dependency references.
- `attacker`: initial host, initial credentials, initially compromised hosts, credential target, lateral target, and collection target.
- `benign_noise`: optional seeded green/admin/mission artifacts such as failed-auth bursts, noisy maintenance scripts, file-access bursts, service-health blips, and ticket spikes. These create suspicious telemetry without actor-visible benign/malicious labels.
- `sensor_model`: optional telemetry profile with default/category-level `coverage`, `drop_rate`, `delay`, `alert_delay`, and public `sensor_id` values. `--perfect-sensors` overrides this to full coverage, no drops, and zero delay.
- `provenance`: per-field realism anchors with `field`, `taxonomy`, `source`, optional `url`, and `validation_plan`.

The loader validates uniqueness, host/user/service references,
`services[].depends_on`, `mission.dependencies`, workflow task references,
benign-noise references, sensor-model bounds, task cadence, attacker
references, auth-affinity consistency, and provenance completeness. Python may
orchestrate execution, but the default world inventory, users, roles, workflow
tasks, service profiles, criticality, auth-affinity reference, benign-noise
profile, sensor profile, and attacker starting assumptions come from the
fixture.

Workflow task validation requires at least three task types and at least two
user roles when `mission.workflow_tasks` is present. Each workflow task must
name a unique `task_id`, a `workflow_id`, a known user role, known required
services, valid required files, positive priority, and a deadline at or after
the scheduled time. When workflow tasks are present,
`mission.green_task_schedule` is derived from their `scheduled_at` values.

## Taxonomy Mapping

The fixture maps to arXiv 2604.08805v1 as follows:

- `hosts` and `services`: virtualisation gap, network/host simulation. They make asset inventory, criticality, and service roles explicit instead of implicit Python constants.
- `users` and `auth_affinity_dataset`: virtualisation gap, user simulation. The fixture points to LANL-style user-computer associations rather than replacing them with arbitrary uniform users.
- `attacker`: virtualisation gap, threat simulation. The current chain remains small, with CALDERA/Mordor/ATT&CK-style validation planned for action artifacts.
- `mission.workflow_tasks`: modelling gap, sequence modelling, and normal-operation realism. Green work now has named workflows, task types, role requirements, priorities, deadlines, required services/files, and user-facing outcomes instead of a single hardcoded app task.
- `mission.green_task_schedule`: modelling gap, sequence modelling. Green work happens on an event-driven clock with deterministic seeded sampling; DS-28 derives this schedule from workflow tasks when present.
- `mission.dependencies`: modelling gap, action/reward modelling. Mission tasks name their service dependencies so harmful defense and mission disruption remain auditable from trace evidence.
- `mission.service_profiles`: modelling gap, action/reward modelling. Service-specific degraded modes determine whether degraded state blocks work or adds latency that can trigger deadline misses.
- `benign_noise`: virtualisation gap, user/threat simulation. Benign user/admin activity creates mission-plausible suspicious artifacts so defender uncertainty is not just attacker truth with labels removed.
- `sensor_model`: modelling gap, observation modelling. Coverage, delay, dropped events, and alert delay make defender observations partial and time-dependent rather than direct trace truth.
- `provenance`: evaluation beyond episodic reward. Reviewers can inspect which fields are data-grounded now and which are validation plans.

## NCSC Grounding

The NCSC frontier-AI defender guidance emphasizes that defenders retain advantage by shaping their environment, maintaining accurate asset inventories, robust access controls, comprehensive logging, and avoiding automated response that disrupts operations more than the attack. The scenario fixture supports that goal by making asset inventory, identity graph, service dependencies, and mission-criticality assumptions explicit before any policy or model is evaluated.

## DS-20 Calibration Status

The default DS-20 noise and sensor profile is intentionally small and
heuristic. It is shaped by LANL auth/process/service event formats, OpTC
endpoint telemetry structure, ECS/Sigma/Elastic alert conventions, Mordor-style
ambiguous detection artifacts, and the NCSC/arXiv requirement that defender
observations include uncertainty. It is not a statistical reproduction of
LANL/OpTC distributions.

Two ablation switches exist for directionality checks:

- `--no-noise`: disables scenario benign-noise scheduling.
- `--perfect-sensors`: preserves telemetry generation but removes coverage
  misses, drops, visibility delay, and alert delay.

## DS-28 Workflow Status

The default fixture now contains seven mission workflow tasks across
`mission-package-cycle` and `mission-reporting`. The task mix includes
`use_mission_app`, `read_write_file`, `submit_report`, and
`retry_after_failure`, and roles include `mission_analyst` and
`mission_coordinator`. The active mission service records workflow id, task
type, deadline, completion time, latency, degraded state, and ticket status in
trace-ingested telemetry so replay can attribute completed tasks, failed tasks,
deadline misses, blocked dependencies, and ticket backlog to source evidence.

## Adding Scenario Variants

Add variants as new JSON files under `badlands/scenarios/` and pass them with `--scenario`. A variant should change one realism dimension at a time unless it represents a separate mission owner contract. Keep provenance entries current; every realism claim needs a dataset, workflow source, platform source, or explicit validation plan.

Do not use scenario variants to add new harness features, unsafe tooling,
custom actor memory, or campaign state. Those remain separate tickets:

- DS-17: make mission/file/ticket service state more authoritative.
- DS-18: propagate service dependency failures through active services.
- DS-23: build the validity runner.
- DS-29: add durable actor sessions/campaign state with the OpenAI Agents SDK where possible.
