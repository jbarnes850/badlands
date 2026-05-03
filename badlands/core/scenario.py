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
    benign_noise: dict[str, Any]
    sensor_model: dict[str, Any]
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
    def service_ids(self) -> set[str]:
        return {str(service["service_id"]) for service in self.services}

    def service_host(self, service_id: str) -> str:
        for service in self.services:
            if service["service_id"] == service_id:
                return str(service["host_id"])
        raise KeyError(f"unknown scenario service {service_id}")

    @property
    def mission_service_id(self) -> str:
        return str(self.mission.get("task_template", "use_mission_app")).replace("use_", "")

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
        benign_noise=dict(raw.get("benign_noise", {})),
        sensor_model=dict(raw.get("sensor_model", {})),
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
    service_ids = scenario.service_ids
    hosts_by_id = {str(host["host_id"]): host for host in scenario.hosts}
    for user in scenario.users:
        if user["primary_host"] not in host_ids:
            raise ValueError(f"user {user['user_id']} references unknown primary_host {user['primary_host']}")
    for service in scenario.services:
        if service["host_id"] not in host_ids:
            raise ValueError(f"service {service['service_id']} references unknown host_id {service['host_id']}")
        for dependency in service.get("depends_on", []):
            if dependency not in service_ids:
                raise ValueError(f"service {service['service_id']} depends_on unknown service {dependency}")
    for task, dependencies in scenario.mission.get("dependencies", {}).items():
        if not isinstance(dependencies, list):
            raise ValueError(f"mission dependency {task} must be a list")
        for dependency in dependencies:
            if dependency not in host_ids and dependency not in service_ids:
                raise ValueError(f"mission dependency {task} references unknown host/service {dependency}")
    for item in scenario.benign_noise.get("events", []):
        if item.get("host") and item["host"] not in host_ids:
            raise ValueError(f"benign noise event references unknown host {item['host']}")
        if item.get("user") and item["user"] not in user_ids:
            raise ValueError(f"benign noise event references unknown user {item['user']}")
        if item.get("service") and item["service"] not in service_ids:
            raise ValueError(f"benign noise event references unknown service {item['service']}")
    for category, profile in scenario.sensor_model.get("categories", {}).items():
        if not isinstance(profile, dict):
            raise ValueError(f"sensor model category {category} must be an object")
        for key in ("coverage", "drop_rate"):
            if key in profile and not 0 <= float(profile[key]) <= 1:
                raise ValueError(f"sensor model {category}.{key} must be between 0 and 1")
        if "delay" in profile and int(profile["delay"]) < 0:
            raise ValueError(f"sensor model {category}.delay must be non-negative")

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
    protected_assets = attacker.get("protected_assets", [])
    if not isinstance(protected_assets, list) or not protected_assets:
        raise ValueError("attacker.protected_assets must define at least one protected asset")
    asset_ids: set[str] = set()
    for asset in protected_assets:
        asset_id = str(asset.get("asset_id", ""))
        if not asset_id or asset_id in asset_ids:
            raise ValueError("attacker protected assets must have unique asset_id values")
        asset_ids.add(asset_id)
        if asset.get("host_id") not in host_ids:
            raise ValueError(f"attacker protected asset {asset_id} references unknown host")
        if asset.get("service_id") not in service_ids:
            raise ValueError(f"attacker protected asset {asset_id} references unknown service")
        if not asset.get("file"):
            raise ValueError(f"attacker protected asset {asset_id} must define file")
        host = hosts_by_id[str(asset["host_id"])]
        if str(asset["file"]) not in dict(host.get("files", {})):
            raise ValueError(f"attacker protected asset {asset_id} references unknown host file")
    objectives = attacker.get("objectives", [])
    if not isinstance(objectives, list) or not objectives:
        raise ValueError("attacker.objectives must define at least one objective")
    for objective in objectives:
        objective_type = objective.get("type")
        if objective_type not in {"collection", "exfiltration", "disruption"}:
            raise ValueError(f"attacker objective {objective.get('objective_id')} has unsupported type")
        if objective_type in {"collection", "exfiltration"} and objective.get("asset_id") not in asset_ids:
            raise ValueError(f"attacker objective {objective.get('objective_id')} references unknown asset")
        if objective_type == "disruption" and objective.get("service_id") not in service_ids:
            raise ValueError(f"attacker objective {objective.get('objective_id')} references unknown service")

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
