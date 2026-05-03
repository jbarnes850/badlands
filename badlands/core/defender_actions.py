from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DefenderActionSpec:
    action: str
    duration: int
    disruptive: bool = False
    rollbackable: bool = False


DEFENDER_ACTION_SPECS: tuple[DefenderActionSpec, ...] = (
    DefenderActionSpec("triage_alert", 3),
    DefenderActionSpec("query_endpoint", 2),
    DefenderActionSpec("query_identity", 2),
    DefenderActionSpec("query_network", 2),
    DefenderActionSpec("isolate_host", 2, disruptive=True, rollbackable=True),
    DefenderActionSpec("reset_account", 3, disruptive=True, rollbackable=True),
    DefenderActionSpec("block_indicator", 3, disruptive=True, rollbackable=True),
    DefenderActionSpec("kill_process", 2, disruptive=True),
    DefenderActionSpec("restore_host_or_service", 5, rollbackable=True),
    DefenderActionSpec("escalate", 4),
    DefenderActionSpec("rollback", 4),
)

DEFENDER_ACTION_DURATIONS = {spec.action: spec.duration for spec in DEFENDER_ACTION_SPECS}
DEFENDER_ACTIONS = tuple(spec.action for spec in DEFENDER_ACTION_SPECS)
