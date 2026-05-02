# Scenario Fixtures

Badlands scenarios are inspectable realism contracts. They define the mission world being measured before agents act in it. The default fixture is `badlands/scenarios/mission_desk.json`.

## Schema

The current schema is intentionally small:

- `scenario_id`, `name`, `description`: reviewer-facing identity and mission narrative.
- `auth_affinity_dataset`: path to the LANL-derived user-host affinity fixture used for green identity cadence and host assignment.
- `hosts`: host inventory with `host_id`, `role`, `owner`, `criticality`, and optional initial file/process state.
- `users`: mission users with `user_id`, `primary_host`, and optional `credentials_exposed`.
- `services`: service inventory with `service_id`, `host_id`, `kind`, `criticality`, and optional `depends_on`.
- `mission`: task template, green task schedule, and service dependency references.
- `attacker`: initial host, initial credentials, initially compromised hosts, credential target, lateral target, and collection target.
- `provenance`: per-field realism anchors with `field`, `taxonomy`, `source`, optional `url`, and `validation_plan`.

The loader validates uniqueness, host/user/service references, `services[].depends_on`, `mission.dependencies`, task cadence, attacker references, auth-affinity consistency, and provenance completeness. Python may orchestrate execution, but the default world inventory, users, task cadence, criticality, auth-affinity reference, and attacker starting assumptions come from the fixture.

## Taxonomy Mapping

The fixture maps to arXiv 2604.08805v1 as follows:

- `hosts` and `services`: virtualisation gap, network/host simulation. They make asset inventory, criticality, and service roles explicit instead of implicit Python constants.
- `users` and `auth_affinity_dataset`: virtualisation gap, user simulation. The fixture points to LANL-style user-computer associations rather than replacing them with arbitrary uniform users.
- `attacker`: virtualisation gap, threat simulation. The current chain remains small, with CALDERA/Mordor/ATT&CK-style validation planned for action artifacts.
- `mission.green_task_schedule`: modelling gap, sequence modelling. Green work happens on an event-driven clock with deterministic seeded sampling.
- `mission.dependencies`: modelling gap, action/reward modelling. Mission tasks name their service dependencies so harmful defense and mission disruption remain auditable from trace evidence.
- `provenance`: evaluation beyond episodic reward. Reviewers can inspect which fields are data-grounded now and which are validation plans.

## NCSC Grounding

The NCSC frontier-AI defender guidance emphasizes that defenders retain advantage by shaping their environment, maintaining accurate asset inventories, robust access controls, comprehensive logging, and avoiding automated response that disrupts operations more than the attack. The scenario fixture supports that goal by making asset inventory, identity graph, service dependencies, and mission-criticality assumptions explicit before any policy or model is evaluated.

## Adding Scenario Variants

Add variants as new JSON files under `badlands/scenarios/` and pass them with `--scenario`. A variant should change one realism dimension at a time unless it represents a separate mission owner contract. Keep provenance entries current; every realism claim needs a dataset, workflow source, platform source, or explicit validation plan.

Do not use scenario variants to add broad mission workflow semantics, richer service state, dependency propagation, or harness features. Those remain separate tickets:

- DS-17: make mission/file/ticket service state more authoritative.
- DS-18: propagate service dependency failures through active services.
- DS-23: build the validity runner.
- DS-28: scale the mission app into scenario-driven workflows.
