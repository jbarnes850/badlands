from __future__ import annotations

import random
from typing import Any

Action = tuple[str, dict[str, Any]]


def do_nothing_defender(observation: dict[str, Any], *, seed: int = 1, magic: bool = False) -> list[Action]:
    return []


def isolate_everything_defender(observation: dict[str, Any], *, seed: int = 1, magic: bool = False) -> list[Action]:
    inventory = observation.get("inventory", [])
    return [("isolate_host", {"host_id": h["host_id"]}) for h in inventory]


def alert_label_defender(observation: dict[str, Any], *, seed: int = 1, magic: bool = False) -> list[Action]:
    if magic and observation.get("magic", {}).get("suspect_host"):
        return [("isolate_host", {"host_id": observation["magic"]["suspect_host"]})]
    if observation.get("alerts"):
        return [("query_endpoint", {"host_id": "ws-alice"})]
    return []


def evidence_gathering_defender(observation: dict[str, Any], *, seed: int = 1, magic: bool = False) -> list[Action]:
    if not observation.get("alerts"):
        return [("query_endpoint", {"host_id": "ws-alice"}), ("query_network", {"host_id": "ws-alice"})]
    return [
        ("triage_alert", {"alert_id": "latest"}),
        ("query_identity", {"user_id": "alice"}),
        ("query_network", {"host_id": "ws-alice"}),
        ("escalate", {"case_id": "case-latest"}),
        ("reset_account", {"user_id": "bob"}),
        ("reset_account", {"user_id": "carol"}),
        ("isolate_host", {"host_id": "ws-alice"}),
        ("restore_host_or_service", {"target": "mission_app"}),
    ]


def random_defender(observation: dict[str, Any], *, seed: int = 1, magic: bool = False) -> list[Action]:
    rng = random.Random(seed)
    actions: list[Action] = [
        ("query_endpoint", {"host_id": "ws-alice"}),
        ("query_identity", {"user_id": "alice"}),
        ("query_network", {"host_id": "ws-alice"}),
        ("isolate_host", {"host_id": "ws-bob"}),
        ("reset_account", {"user_id": "bob"}),
        ("block_indicator", {"type": "host", "value": "app-1", "scope": "enclave"}),
    ]
    return [rng.choice(actions) for _ in range(3)]


POLICIES = {
    "do_nothing": do_nothing_defender,
    "isolate_everything": isolate_everything_defender,
    "alert_label": alert_label_defender,
    "evidence_gathering": evidence_gathering_defender,
    "random": random_defender,
}
