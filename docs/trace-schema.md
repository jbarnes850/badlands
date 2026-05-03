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

Dependency propagation is recorded as `dependency_state_changed`; mission and security score evidence may cite those events through `source_event_ids`.

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
