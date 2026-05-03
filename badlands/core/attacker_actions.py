from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackerActionSpec:
    action: str
    duration: int


ATTACKER_ACTION_SPECS: tuple[AttackerActionSpec, ...] = (
    AttackerActionSpec("discover_local", 3),
    AttackerActionSpec("scan_network", 5),
    AttackerActionSpec("attempt_credential_access", 6),
    AttackerActionSpec("establish_persistence", 4),
    AttackerActionSpec("lateral_move", 5),
    AttackerActionSpec("collect", 6),
    AttackerActionSpec("exfiltrate", 7),
    AttackerActionSpec("disrupt_service", 4),
)

ATTACKER_ACTION_DURATIONS = {spec.action: spec.duration for spec in ATTACKER_ACTION_SPECS}
ATTACKER_ACTIONS = tuple(spec.action for spec in ATTACKER_ACTION_SPECS)
