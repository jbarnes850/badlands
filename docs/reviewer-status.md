# Reviewer Status

## Satisfied in this vertical slice

- Four-component architecture represented in code: attacker actions, defender actions, seeded green simulator, active network environment.
- Append-only trace writer with JSON-schema validation.
- Required event types emitted during smoke episode.
- Separate observation views with forbidden-field leak tests; defender action results no longer expose `true_positive` labels.
- Event-driven timing with delayed actions and a timing-outcome test.
- Green mission tasks produce mission value, telemetry, tickets, and disruption penalties; green user choice has a `UserSimulator` / `GreenUserLLM` interface with deterministic cache/replay tests.
- Defender actions implemented: `triage_alert`, `query_endpoint`, `query_identity`, `isolate_host`, `reset_account`, `rollback`.
- Attacker actions implemented for local enclave only: `discover_local`, `scan_network`, `attempt_credential_access`, `establish_persistence`, `lateral_move`, `collect`, `exfiltrate`, `disrupt_service`.
- Scoring derives from trace and has replay test.
- Baseline defender policies implemented.
- Ablation tests cover no persistence, magic-observation rejection, and no green users.
- Docker Compose provides a contained local mission web/file/ticket service surface; integration test starts the HTTP service, routes green and attacker actions through it, ingests service logs, and converts them to telemetry.
- LANL-derived auth-affinity fixture initializes user-host affinities and non-uniform green auth background.
- `magic_observations` now changes reviewer-only alert-label policy behavior and is tested directionally.
- Live LLM client now performs JSON-object prompting, larger token budgets, markdown/object extraction, and repair retries for truncated/malformed responses.
- CLI can run Green/Attacker/Defender LLM actors in actual episodes via `--green-actor llm`, `--attacker-actor llm`, and `--defender-actor llm`; attacker/defender LLM decisions are now scheduled closed-loop (`observe -> decide -> request action -> wait for completion -> observe again`) rather than batch-proposed at timestamp 0. Baseline policies receive defender observations and return action proposals instead of receiving `MissionDeskEnv`.
- Mission service logs carry run ids and `/logs?run_id=...` prevents stale cross-episode ingestion.
- Mission service has authoritative availability state for `/health`; `/admin/isolate_app` changes service health and is covered by integration test.
- Local IdP service is active for identity truth: login, session validation, credential use, reset/lockout, and rollback now go through HTTP endpoints rather than direct Python identity mutation.
- Green mission app access requires IdP-issued session state; mission failures from lockout or invalid sessions cite IdP/auth telemetry evidence.
- Defender `reset_account` calls `/idp/reset`, ingests IdP logs, mirrors lockout only after service evidence, and produces harmful-defense evidence when appropriate.
- Attacker credential access and lateral movement depend on IdP credential validation; reset races can invalidate in-flight lateral movement.
- IdP auth telemetry is trace-visible as ECS-like `auth` telemetry with user, source host, destination/service, outcome, reason, run id, timestamp, and optional session id.
- TP/FP scoring is no longer derived from hidden audit labels; it is inferred from prior security-impact events plus defender action targets.
- Invalid LLM decisions are no longer coerced into allowed actions. They emit `llm_decision_invalid` trace events and do not create action requests.
- Green LLM observations include durable user identity, role, host, workflow counters, and recent ticket history.
- Score snapshots include an evidence map from nonzero score fields to source event ids.
- Identity realism tests now show IdP state changes measured security risk, and lockout-related mission harm remains trace-derived.
- Mission Desk world definition now loads from `badlands/scenarios/mission_desk.json`: hosts, users, services, green cadence, mission dependencies, criticality, auth-affinity reference, and attacker starting assumptions are scenario fixture fields.
- Scenario fixture provenance maps realism assumptions to dataset/workflow/platform anchors and to arXiv virtualisation/modelling-gap categories.
- Mission app, file share, and ticket outcomes are now service-authoritative for the current compact workflow: `/mission/task`, `/file/<name>`, `/ticket`, `/tickets`, and `/ticket/update` own service state and emit trace-ingested telemetry.
- Green `use_mission_app`, `read_write_file`, and `create_ticket` outcomes route through active service endpoints. Mission task trace events cite service/auth/ticket evidence in `source_event_ids`.
- File access requires IdP session validation and emits both auth validation telemetry and service `file_read` telemetry.
- Defender ticket visibility is role-valid: tickets appear through service telemetry and mission/ticket trace artifacts, not hidden service state.
- Dependency graph is now first-class for hosts, services, users, telemetry, and mission tasks. Propagated `available`/`degraded`/`unavailable` state changes emit `dependency_state_changed` trace events and are pushed into active service endpoints.
- Defender host isolation and rollback now propagate through service dependencies. Attacker collection from the file-share tier can degrade the file-share dependency and produce mission/security score impact through trace evidence.
- Replay evidence for service downtime includes dependency-state source events, so blocked dependencies remain auditable from the JSONL trace.
- Scenario-defined protected assets and attacker objectives now gate
  collection, exfiltration, and mission-app disruption. Objective completion
  emits trace-backed telemetry and `security_impact_event` records, and replay
  scores sensitive collection, exfiltration units, service disruption, and
  overall security impact from those events.
- Mission workflows are now scenario-driven: the default fixture defines
  multiple workflow ids, task types, deadlines, priorities, required roles,
  required services/files, and user-facing outcomes.
- The active mission service resolves scenario workflow tasks, enforces role
  and dependency requirements, records service-specific degraded-mode latency
  or failure, and emits ECS-like telemetry with workflow/task/deadline/latency
  fields.
- Green observations include role-valid task context, deadlines, priority,
  ticket history, and prior user-experienced outcomes without exposing hidden
  dependency state or scorer truth.
- Replay scoring now includes `deadline_minutes_lost` and
  `ticket_backlog_count`; nonzero mission fields cite trace evidence through
  `score_snapshot.evidence`.
- Live validation green observations use scenario workflow tasks rather than
  synthetic `task-live-*` placeholders, so qualitative model-output inspection
  sees the same mission workflow surface as offline episodes.
- Live validation reports include DS-27 `decision_quality` summaries derived
  from trace-visible LLM decision events: repeated actions, evidence-id
  grounding, unsupported evidence ids, suspected hidden-state claims, defender
  blast-radius/overreaction cues, and green SOC-like behavior.

## Intentionally incomplete

- Some episode actions are still applied in the event core rather than through containers. Risk: not all telemetry is service-generated. Next step: route defender access-control for hosts/users and more attacker file/scan behavior through compose services.
- IdP and mission app currently share one local Python HTTP process. Risk: fewer deployment and network-boundary side effects than a separately deployed IdP container. Next step: split the IdP into its own compose service once this identity-state contract is stable.
- Email is represented through ticket-like artifacts, not SMTP/IMAP. Risk: less realistic phishing/report workflow. Next step: add local MailHog-style service or stdlib mailbox endpoint.
- Durations/rates are contract-informed constants, not yet calibrated from OpTC/LANL/CALDERA. Next step: add calibration fixtures and cite per-action sources.
- Degraded-mode semantics are service-specific but still heuristic. Risk:
  workflow latency and failure modes are not calibrated to mission-owner
  artifacts. Next step: DS-25/DS-26 provenance/calibration.
- Mission workflows are richer but still compact. Risk: email/reporting is
  represented by app/ticket tasks rather than full SMTP/IMAP/reporting systems.
  Next step: add a contained email/reporting service only if required by a
  mission source pack.
- DS-22 attacker objective prerequisites and artifacts are ATT&CK-shaped but
  not yet statistically calibrated to Mordor/OpTC/CALDERA traces. Next step:
  DS-25/DS-26 provenance and calibration.
