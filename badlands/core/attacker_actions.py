from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackerActionSpec:
    action: str
    duration: int
    calibration_id: str | None = None


ATTACKER_ACTION_SPECS: tuple[AttackerActionSpec, ...] = (
    AttackerActionSpec("discover_local", 3),
    AttackerActionSpec("scan_network", 5, "cal.scan_network.replay_hooks.v1"),
    AttackerActionSpec("attempt_credential_access", 6, "cal.credential_access.idp_replay_hooks.v1"),
    AttackerActionSpec("establish_persistence", 4),
    AttackerActionSpec("lateral_move", 5, "cal.lateral_move.idp_replay_hooks.v1"),
    AttackerActionSpec("collect", 6, "cal.collect.file_share_hooks.v1"),
    AttackerActionSpec("exfiltrate", 7),
    AttackerActionSpec("disrupt_service", 4),
)

ATTACKER_ACTION_DURATIONS = {spec.action: spec.duration for spec in ATTACKER_ACTION_SPECS}
ATTACKER_ACTION_CALIBRATION_IDS = {
    spec.action: spec.calibration_id for spec in ATTACKER_ACTION_SPECS if spec.calibration_id
}
ATTACKER_ACTIONS = tuple(spec.action for spec in ATTACKER_ACTION_SPECS)
