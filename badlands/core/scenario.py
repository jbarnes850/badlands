from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_SCENARIO_PATH = Path(__file__).parents[1] / "scenarios" / "mission_desk.json"


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    name: str
    description: str
    auth_affinity_dataset: str
    hosts: list[dict[str, Any]]
    users: list[dict[str, Any]]
    services: list[dict[str, Any]]
    mission: dict[str, Any]
    attacker: dict[str, Any]
    provenance: list[dict[str, Any]]
    source_path: Path = field(compare=False)

    @property
    def green_task_schedule(self) -> list[int]:
        return [int(t) for t in self.mission.get("green_task_schedule", [])]

    @property
    def host_ids(self) -> set[str]:
        return {str(host["host_id"]) for host in self.hosts}

    @property
    def user_ids(self) -> set[str]:
        return {str(user["user_id"]) for user in self.users}

    @property
    def auth_affinity_path(self) -> Path:
        path = Path(self.auth_affinity_dataset)
        return path if path.is_absolute() else Path(__file__).parents[2] / path


def load_scenario(path: Path | str = DEFAULT_SCENARIO_PATH) -> Scenario:
    scenario_path = Path(path)
    raw = json.loads(scenario_path.read_text())
    scenario = Scenario(
        scenario_id=str(raw["scenario_id"]),
        name=str(raw["name"]),
        description=str(raw["description"]),
        auth_affinity_dataset=str(raw["auth_affinity_dataset"]),
        hosts=list(raw["hosts"]),
        users=list(raw["users"]),
        services=list(raw.get("services", [])),
        mission=dict(raw["mission"]),
        attacker=dict(raw["attacker"]),
        provenance=list(raw.get("provenance", [])),
        source_path=scenario_path,
    )
    validate_scenario(scenario)
    return scenario


def validate_scenario(scenario: Scenario) -> None:
    if not scenario.hosts:
        raise ValueError("scenario must define at least one host")
    if not scenario.users:
        raise ValueError("scenario must define at least one user")
    if not scenario.green_task_schedule:
        raise ValueError("scenario mission.green_task_schedule must not be empty")
    _require_unique("host_id", scenario.hosts, "hosts")
    _require_unique("user_id", scenario.users, "users")
    _require_unique("service_id", scenario.services, "services")

    host_ids = scenario.host_ids
    user_ids = scenario.user_ids
    for user in scenario.users:
        if user["primary_host"] not in host_ids:
            raise ValueError(f"user {user['user_id']} references unknown primary_host {user['primary_host']}")
    for service in scenario.services:
        if service["host_id"] not in host_ids:
            raise ValueError(f"service {service['service_id']} references unknown host_id {service['host_id']}")

    attacker = scenario.attacker
    if attacker["initial_host"] not in host_ids:
        raise ValueError("attacker.initial_host must reference a scenario host")
    for user_id in attacker.get("initial_credentials", []):
        if user_id not in user_ids:
            raise ValueError(f"attacker initial credential references unknown user {user_id}")
    for host_id in attacker.get("initial_compromised_hosts", []):
        if host_id not in host_ids:
            raise ValueError(f"attacker initial compromised host references unknown host {host_id}")
    if attacker.get("credential_target_user") not in user_ids:
        raise ValueError("attacker.credential_target_user must reference a scenario user")
    if attacker.get("lateral_target_host") not in host_ids:
        raise ValueError("attacker.lateral_target_host must reference a scenario host")

    if not scenario.provenance:
        raise ValueError("scenario must include provenance entries")
    for entry in scenario.provenance:
        for key in ("field", "taxonomy", "source", "validation_plan"):
            if not entry.get(key):
                raise ValueError(f"scenario provenance entry missing {key}")


def _require_unique(field_name: str, items: list[dict[str, Any]], label: str) -> None:
    values = [item[field_name] for item in items]
    if len(values) != len(set(values)):
        raise ValueError(f"scenario {label} must have unique {field_name} values")
