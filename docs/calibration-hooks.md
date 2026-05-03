# Action Calibration Hooks

DS-26 adds a read-only calibration surface for high-impact abstract actions.
The goal is auditability, not precision. A calibration record says which source
family can later validate an action's preconditions, artifacts, duration range,
and success/failure notes. It does not run a cyber range or certify the current
heuristics as measured.

## Record Schema

Records live in `badlands/calibration/action_calibration.json` and are loaded by
`badlands.core.calibration`.

Required fields:

- `id`: stable calibration record id.
- `action`: Badlands action name.
- `source` and `source_urls`: source families and primary anchors.
- `status`: `calibrated`, `heuristic`, or `unvalidated`.
- `preconditions`: what must be true before the action is meaningful.
- `expected_artifacts`: trace/telemetry artifacts the action should create.
- `duration_range`: expected minute range from the environment contract or
  source plan.
- `success_notes` and `failure_notes`: bounded outcome notes.
- `confidence`: `low`, `medium`, or `high`.

Current DS-26 records are intentionally `heuristic` with `low` confidence.
They reference source families such as Mordor/OTRF, OpTC, LANL, CALDERA,
Cyberwheel, NASimEmu, NIST/CISA, NCSC, and ATT&CK, but none claim measured
calibration yet.

## Implemented Hooks

`MissionDeskEnv.request()` emits calibration metadata on every
`action_started` event:

- known records include `record_id`, `status`, `confidence`, sources,
  preconditions, expected artifacts, duration range, applied duration, and a
  warning such as `heuristic_calibration_not_validated`;
- missing records emit `status=unvalidated` and
  `warnings=["missing_calibration_record"]`.

The JSONL trace remains canonical. Replay scores are still derived from trace
events only and do not reload calibration fixtures.

Initial records cover:

- attacker: `scan_network`, `attempt_credential_access`, `lateral_move`,
  `collect`;
- defender: `isolate_host`, `reset_account`, `restore_host_or_service`.

## Adding Higher-Fidelity Evidence Later

Safe future additions should create or update records with direct evidence
paths, not execute tools inside ordinary tests:

- CALDERA: map a contained ability or operation report to Badlands action
  preconditions, artifacts, and elapsed time.
- Mordor/OpTC: map replay trace examples to expected ECS-like artifacts and
  alert evidence.
- NASimEmu: compare abstract network attack actions against controlled
  emulation transfer logs.
- Cyberwheel: compare detector/alert and simulation/emulation campaign
  structure for action/observation parity.

Status may move from `heuristic` to `calibrated` only when the record cites
reviewable evidence artifacts and tests verify the claim. Unsafe exploit
execution, external scanning, uncontained egress, and full simulator-emulator
bridges remain out of scope for DS-26.
