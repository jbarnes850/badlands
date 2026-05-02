from __future__ import annotations

from dataclasses import dataclass, field

from badlands.core.datasets import load_auth_affinities


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
    auth_affinities: dict = field(default_factory=dict)


def initial_state(seed: int = 1, *, no_persistence: bool = False, no_green: bool = False) -> WorldState:
    state = WorldState(seed=seed)
    state.hosts = {
        "ws-alice": Host("ws-alice", "workstation", "alice", 2, compromised=True),
        "ws-bob": Host("ws-bob", "workstation", "bob", 2),
        "ws-carol": Host("ws-carol", "workstation", "carol", 1),
        "ws-dave": Host("ws-dave", "workstation", "dave", 1),
        "ws-erin": Host("ws-erin", "workstation", "erin", 1),
        "ws-frank": Host("ws-frank", "workstation", "frank", 1),
        "ws-grace": Host("ws-grace", "workstation", "grace", 1),
        "ws-heidi": Host("ws-heidi", "workstation", "heidi", 1),
        "ws-ivan": Host("ws-ivan", "workstation", "ivan", 1),
        "ws-judy": Host("ws-judy", "workstation", "judy", 1),
        "ws-mallory": Host("ws-mallory", "workstation", "mallory", 1),
        "ws-oscar": Host("ws-oscar", "workstation", "oscar", 1),
        "files-1": Host("files-1", "file_share", "svc-files", 5, files={"mission.txt": "target package"}),
        "app-1": Host("app-1", "mission_app", "svc-app", 5),
        "idp-1": Host("idp-1", "identity", "svc-idp", 5),
    }
    affinities = load_auth_affinities()
    state.auth_affinities = affinities
    state.users = {
        user_id: User(user_id, affinity.host_id, credentials_exposed=(user_id == "alice"))
        for user_id, affinity in affinities.items()
    }
    if no_persistence:
        state.hosts["ws-alice"].persistence = False
    if no_green:
        state.users = {}
    return state
