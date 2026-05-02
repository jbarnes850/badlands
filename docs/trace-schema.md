# Trace Schema

Trace events are JSON Lines validated by `badlands/schemas/trace_event.schema.json`.

Required top-level fields:

- `event_id`: stable monotonic id, e.g. `evt_000001`.
- `type`: one of `action_requested`, `action_started`, `action_completed`, `state_transition`, `telemetry_emitted`, `alert_emitted`, `observation_delivered`, `mission_task_event`, `defense_harm_event`, `security_impact_event`, `score_snapshot`, `llm_decision_invalid`, `action_rejected`.
- `timestamp`: integer environment-clock minute.
- `agent`: `attacker`, `defender`, `green`, or `null`.
- `parents`: source event ids.
- `payload`: event-specific object.

Scoring replay uses only trace events. Agent observation views must reference event/artifact payloads and must not expose hidden fields such as `host_compromised`, `attacker_location`, `credential_stolen`, `credentials_exposed`, `scoring`, or `objective_state`.
