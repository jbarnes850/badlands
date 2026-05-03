from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from badlands.core.datasets import AuthAffinity, load_auth_affinities
from badlands.core.scenario import Scenario, load_scenario


@dataclass
class Host:
    host_id: str
    role: str
    owner: str
    criticality: int
    isolated: bool = False
    compromised: bool = False
    persistence: bool = False
    files: dict[str, str] = field(default_factory=dict)
    processes: list[str] = field(default_factory=list)


@dataclass
class User:
    user_id: str
    host_id: str
    locked: bool = False
    credentials_exposed: bool = False


@dataclass
class WorldState:
    seed: int
    users: dict[str, User] = field(default_factory=dict)
    hosts: dict[str, Host] = field(default_factory=dict)
    attacker_host: str = "ws-alice"
    attacker_credentials: set[str] = field(default_factory=lambda: {"alice"})
    collected_files: set[str] = field(default_factory=set)
    mission_completed: int = 0
    mission_failed: int = 0
    tickets: list[dict] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    telemetry: list[dict] = field(default_factory=list)
    cases: list[dict] = field(default_factory=list)
    blocked_indicators: set[tuple[str, str]] = field(default_factory=set)
    auth_affinities: dict[str, AuthAffinity] = field(default_factory=dict)
    scenario: Scenario | None = None


def initial_state(
    seed: int = 1,
    *,
    no_persistence: bool = False,
    no_green: bool = False,
    scenario: Scenario | Path | str | None = None,
) -> WorldState:
    loaded = scenario if isinstance(scenario, Scenario) else load_scenario(scenario) if scenario else load_scenario()
    attacker = loaded.attacker
    state = WorldState(
        seed=seed,
        attacker_host=str(attacker["initial_host"]),
        attacker_credentials=set(attacker.get("initial_credentials", [])),
        scenario=loaded,
    )
    compromised_hosts = set(attacker.get("initial_compromised_hosts", []))
    state.hosts = {host["host_id"]: _host_from_fixture(host, compromised_hosts) for host in loaded.hosts}
    affinities = load_auth_affinities(loaded.auth_affinity_path)
    state.auth_affinities = affinities
    state.users = {user["user_id"]: _user_from_fixture(user, affinities) for user in loaded.users}
    if no_persistence:
        for host in state.hosts.values():
            host.persistence = False
    if no_green:
        state.users = {}
    return state


def _host_from_fixture(data: dict[str, Any], compromised_hosts: set[str]) -> Host:
    host_id = str(data["host_id"])
    return Host(
        host_id=host_id,
        role=str(data["role"]),
        owner=str(data["owner"]),
        criticality=int(data["criticality"]),
        compromised=host_id in compromised_hosts,
        files=dict(data.get("files", {})),
        processes=list(data.get("processes", [])),
    )


def _user_from_fixture(data: dict[str, Any], affinities: dict[str, AuthAffinity]) -> User:
    user_id = str(data["user_id"])
    affinity = affinities.get(user_id)
    host_id = affinity.host_id if affinity is not None else str(data["primary_host"])
    if host_id != data["primary_host"]:
        raise ValueError(f"user {user_id} fixture primary_host does not match auth-affinity dataset")
    return User(user_id, host_id, credentials_exposed=bool(data.get("credentials_exposed", False)))
