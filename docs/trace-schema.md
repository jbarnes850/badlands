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

Valid LLM actor decisions are recorded as `llm_decision` events with the supplied observation, raw model decision, constrained `evidence_ids`, rationale, expected effect, and risk. Invalid decisions are recorded as `llm_decision_invalid` and do not schedule an action.

Dependency propagation is recorded as `dependency_state_changed`; mission and security score evidence may cite those events through `source_event_ids`.
