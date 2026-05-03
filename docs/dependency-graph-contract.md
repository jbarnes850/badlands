# Dependency Graph Contract

DS-18 adds a first-class dependency graph for the Mission Desk enclave. The graph is built from the scenario fixture and covers hosts, services, users, mission tasks, and the telemetry surface. It is causal: changing an upstream dependency changes propagated service state, service endpoints, mission task outcomes, and trace-derived scoring.

## Node Types

- `host:<host_id>`: workstation or service host inventory.
- `service:<service_id>`: IdP, mission app, file share, ticket surface, and telemetry.
- `user:<user_id>`: mission user tied to a primary host and identity service.
- `task:<task_name>`: mission workflow dependency set from the scenario fixture.

Static dependency edges are role-valid inventory for defenders. Runtime dependency state is not directly exposed to agents; it becomes visible through health checks, service telemetry, tickets, action results, and `dependency_state_changed` trace evidence.

## States

Each node has an explicit and propagated state:

- `available`: dependency is usable.
- `degraded`: dependency is reachable but cannot reliably support current mission work.
- `unavailable`: dependency cannot support current mission work.

Propagation is monotonic for the current slice: an unavailable upstream makes downstream dependents unavailable; a degraded upstream makes downstream dependents degraded unless another upstream is unavailable.

## Service Effects

The environment computes propagated dependency state and pushes service-state changes into the local mission service. Service endpoints then enforce that state:

- IdP login, session validation, and credential use fail when `service:idp` is degraded or unavailable.
- File reads fail when `service:file_share` is degraded or unavailable.
- Mission task recording fails when `service:mission_app` or required file-share state is degraded or unavailable.
- Ticket creation fails when `service:ticket` is degraded or unavailable.

Python may schedule dependency changes and mirror observed results, but mission/file/ticket outcomes remain service responses and trace-ingested telemetry.

## Trace Evidence

Dependency changes emit `dependency_state_changed` events with node id, kind, reference, previous status, new status, reason, source node, and source event ids. Propagated service degradation/unavailability also emits mission-impact evidence:

- `defense_harm_event` with `field=service_downtime_minutes` for service downtime.
- `security_impact_event` with `kind=service_disruption` when attacker action causes service degradation.
- Service telemetry from `/admin/service_state`, `/file/<name>`, `/mission/task`, and related endpoints.

Replay includes dependency source ids in score evidence so reviewers can reconstruct why mission/security scores moved.

## Source Grounding

NCSC frontier-AI guidance motivates measuring defensive blast radius and mission continuity rather than rewarding shutdown policies. The arXiv 2604.08805 taxonomy maps this slice to sequence, observation, action, and reward modelling: dependency changes happen over time, are observed through artifacts, affect action outcomes, and influence replayable mission/security reward. NIST SP 800-61 and the CISA playbook anchor containment and recovery as operational actions with evidence, communication, and restoration costs.

## Deferred Work

- DS-20: sensor delay/drop and benign health-noise calibration.
- DS-21: richer restore/escalation/case workflows.
- DS-23: validity runner for dependency/no-dependency ablations.
- DS-24: live inference harness reporting for endpoint liveness and role isolation.
- DS-28: richer scenario-defined mission workflows, task deadlines, and degraded-mode semantics.
- DS-29: campaign harness and role-isolated memory over repeated episodes.
