from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DefenderActionSpec:
    action: str
    duration: int
    disruptive: bool = False
    rollbackable: bool = False
    calibration_id: str | None = None


DEFENDER_ACTION_SPECS: tuple[DefenderActionSpec, ...] = (
    DefenderActionSpec("triage_alert", 3),
    DefenderActionSpec("query_endpoint", 2),
    DefenderActionSpec("query_identity", 2),
    DefenderActionSpec("query_network", 2),
    DefenderActionSpec(
        "isolate_host",
        2,
        disruptive=True,
        rollbackable=True,
        calibration_id="cal.isolate_host.response_hooks.v1",
    ),
    DefenderActionSpec(
        "reset_account",
        3,
        disruptive=True,
        rollbackable=True,
        calibration_id="cal.reset_account.idp_response_hooks.v1",
    ),
    DefenderActionSpec("block_indicator", 3, disruptive=True, rollbackable=True),
    DefenderActionSpec("kill_process", 2, disruptive=True),
    DefenderActionSpec(
        "restore_host_or_service",
        5,
        rollbackable=True,
        calibration_id="cal.restore_host_or_service.response_hooks.v1",
    ),
    DefenderActionSpec("escalate", 4),
    DefenderActionSpec("rollback", 4),
)

DEFENDER_ACTION_DURATIONS = {spec.action: spec.duration for spec in DEFENDER_ACTION_SPECS}
DEFENDER_ACTION_CALIBRATION_IDS = {
    spec.action: spec.calibration_id for spec in DEFENDER_ACTION_SPECS if spec.calibration_id
}
DEFENDER_ACTIONS = tuple(spec.action for spec in DEFENDER_ACTION_SPECS)
