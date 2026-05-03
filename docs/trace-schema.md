# Trace Schema

Trace events are JSON Lines validated by `badlands/schemas/trace_event.schema.json`.

Required top-level fields:

- `event_id`: stable monotonic id, e.g. `evt_000001`.
- `type`: one of `action_requested`, `action_started`, `action_completed`, `state_transition`, `dependency_state_changed`, `telemetry_emitted`, `alert_emitted`, `observation_delivered`, `mission_task_event`, `defense_harm_event`, `security_impact_event`, `score_snapshot`, `llm_decision`, `llm_decision_invalid`, `action_rejected`.
- `timestamp`: integer environment-clock minute.
- `agent`: `attacker`, `defender`, `green`, or `null`.
- `parents`: source event ids.
- `payload`: event-specific object.

Scoring replay uses only trace events. Agent observation views must reference event/artifact payloads and must not expose hidden fields such as `host_compromised`, `attacker_location`, `credential_stolen`, `credentials_exposed`, `scoring`, or `objective_state`.

Valid LLM actor decisions are recorded as `llm_decision` events with the supplied observation, raw model decision, constrained `evidence_ids`, rationale, expected effect, and risk. Live LLM runs also include `inference_telemetry`: role, endpoint, model, cache key/path, cache hit/miss, prompt token estimate, completion tokens, wall latency, attempt count, repair count/attempts, parse failure counts, validation error, invalid-decision reason, malformed `raw_outputs` when repair fails, and optional SDK correlation IDs. Invalid decisions are recorded as `llm_decision_invalid` and do not schedule an action; their raw malformed outputs must remain inspectable from the trace/report.

DS-27 live reports derive `decision_quality` from these LLM decision events.
The derived report is not canonical state and is not used for replay scoring.
It exists so reviewers can inspect role-specific behavior, repeated actions,
evidence grounding, unsupported evidence ids, hidden-state claims,
blast-radius/mission reasoning, and green SOC-like language without reading
hidden simulator state.

Dependency propagation is recorded as `dependency_state_changed`; mission and security score evidence may cite those events through `source_event_ids`.

Attacker objective progress is recorded as trace-backed
`security_impact_event` records rather than hidden objective state:

- `kind=collection` cites the protected asset, file, host, service, and source
  action event ids.
- `kind=exfiltration` cites the protected asset, file, contained egress sink,
  exfiltration units, and source action event ids.
- `kind=service_disruption` cites the affected service, dependency status,
  disruption reason, and dependency-state source event ids.

Replay scores `sensitive_files_accessed_count`, `exfiltration_units`, and
`service_disruption_count` from these events and their cited evidence.

Defender workflow actions emit delayed `action_completed` results and a paired
`observation_delivered` event. Query and triage actions expose only role-valid
artifacts such as source event ids, visible telemetry slices, case notes, and
network/auth summaries. Disruptive actions such as host isolation, account
reset, indicator blocks, and process termination must emit trace-backed service,
dependency, mission, or defense-harm evidence when they affect operations.
Audit-only assessment state may appear in trace `state_transition` records, but
must not appear in defender observations or live `llm_decision.observation`
payloads.

DS-26 action calibration hooks add a `calibration` object to each
`action_started` payload. Known records include source families, record id,
status, confidence, preconditions, expected artifacts, duration range, applied
duration, and warnings. Missing records emit `status=unvalidated` with
`missing_calibration_record`. This metadata is reviewer/audit evidence only:
replay does not load calibration fixtures, and heuristic records must not be
treated as measured emulation results.

Telemetry events include a `sensor` object when emitted through the Mission Desk
runtime:

- `sensor_id`: public sensor/log-pipeline identifier.
- `covered`: whether this telemetry category was in sensor coverage.
- `dropped`: whether the event was dropped before defender visibility.
- `visibility_delay` and `visible_at`: when the event becomes observable to the
  defender.
- `alert_delay`: additional detection delay before alert emission.
- `mode`: `scenario` or `perfect` for ablation runs.

Raw `telemetry_emitted` events remain in the canonical trace for replay and
audit, but defender observations filter out events that are not covered, are
dropped, or are not yet visible at the environment clock. Alerts are emitted
only after the configured visibility and alert delay, and they cite source
telemetry ids. Benign-noise provenance is recorded as `state_transition`
metadata and overlapping telemetry/alert artifacts, not as actor-visible
benign/malicious labels.

DS-29 campaign continuity uses ordinary `state_transition` records rather than
new trace event types. `kind=campaign_step_started` records campaign id, step,
memory mode, SDK mode, and per-role SDK session ids. Before a role receives
step-2 memory, the harness emits `kind=campaign_memory_visible` with the
current role, current campaign step, a memory summary, a current-trace event id,
and upstream source trace/event ids. Actors cite the current-trace memory event
id; reviewers can follow that event back to the prior step trace. Replay does
not read SDK sessions or campaign reports.
