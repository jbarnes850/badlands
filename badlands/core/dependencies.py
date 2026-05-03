from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from badlands.core.scenario import Scenario

AVAILABLE = "available"
DEGRADED = "degraded"
UNAVAILABLE = "unavailable"
SERVICE_STATES = {AVAILABLE, DEGRADED, UNAVAILABLE}


@dataclass(frozen=True)
class DependencyNode:
    node_id: str
    kind: str
    ref: str
    label: str


@dataclass
class DependencyGraph:
    nodes: dict[str, DependencyNode]
    dependencies: dict[str, set[str]]
    explicit_states: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for node_id in self.nodes:
            self.explicit_states.setdefault(node_id, AVAILABLE)

    def set_state(self, node_id: str, state: str) -> None:
        if node_id not in self.nodes:
            raise KeyError(f"unknown dependency node {node_id}")
        if state not in SERVICE_STATES:
            raise ValueError(f"unknown dependency state {state}")
        self.explicit_states[node_id] = state

    def effective_states(self) -> dict[str, str]:
        states = dict(self.explicit_states)
        changed = True
        while changed:
            changed = False
            for node_id, upstreams in self.dependencies.items():
                upstream_states = [states.get(dep, AVAILABLE) for dep in upstreams]
                propagated = _combine_state(states.get(node_id, AVAILABLE), upstream_states)
                if states.get(node_id) != propagated:
                    states[node_id] = propagated
                    changed = True
        return states

    def impacted_by(self, upstream: str, states: dict[str, str]) -> list[str]:
        impacted: list[str] = []
        for node_id in sorted(self.nodes):
            if node_id == upstream:
                continue
            if upstream in self.transitive_dependencies(node_id) and states.get(node_id) != AVAILABLE:
                impacted.append(node_id)
        return impacted

    def transitive_dependencies(self, node_id: str) -> set[str]:
        seen: set[str] = set()
        stack = list(self.dependencies.get(node_id, set()))
        while stack:
            dep = stack.pop()
            if dep in seen:
                continue
            seen.add(dep)
            stack.extend(self.dependencies.get(dep, set()))
        return seen

    def service_states(self) -> dict[str, str]:
        states = self.effective_states()
        return {
            node.ref: states[node_id]
            for node_id, node in self.nodes.items()
            if node.kind == "service"
        }


def build_dependency_graph(scenario: Scenario) -> DependencyGraph:
    nodes: dict[str, DependencyNode] = {}
    dependencies: dict[str, set[str]] = {}

    for host in scenario.hosts:
        host_id = str(host["host_id"])
        _add(nodes, dependencies, f"host:{host_id}", "host", host_id, host_id)

    for service in scenario.services:
        service_id = str(service["service_id"])
        node_id = f"service:{service_id}"
        _add(nodes, dependencies, node_id, "service", service_id, service_id)
        dependencies[node_id].add(f"host:{service['host_id']}")
        for dependency in service.get("depends_on", []):
            dependencies[node_id].add(f"service:{dependency}")

    if "service:telemetry" not in nodes:
        _add(nodes, dependencies, "service:telemetry", "service", "telemetry", "telemetry")

    for user in scenario.users:
        user_id = str(user["user_id"])
        node_id = f"user:{user_id}"
        _add(nodes, dependencies, node_id, "user", user_id, user_id)
        dependencies[node_id].add(f"host:{user['primary_host']}")
        if "service:idp" in nodes:
            dependencies[node_id].add("service:idp")

    service_ids = scenario.service_ids
    host_ids = scenario.host_ids
    for task, refs in scenario.mission.get("dependencies", {}).items():
        node_id = f"task:{task}"
        _add(nodes, dependencies, node_id, "task", str(task), str(task))
        for ref in refs:
            if ref in service_ids:
                dependencies[node_id].add(f"service:{ref}")
            elif ref in host_ids:
                dependencies[node_id].add(f"host:{ref}")

    return DependencyGraph(nodes, dependencies)


def _add(
    nodes: dict[str, DependencyNode],
    dependencies: dict[str, set[str]],
    node_id: str,
    kind: str,
    ref: str,
    label: str,
) -> None:
    nodes[node_id] = DependencyNode(node_id, kind, ref, label)
    dependencies.setdefault(node_id, set())


def _combine_state(own_state: str, upstream_states: list[str]) -> str:
    if own_state == UNAVAILABLE or UNAVAILABLE in upstream_states:
        return UNAVAILABLE
    if own_state == DEGRADED or DEGRADED in upstream_states:
        return DEGRADED
    return AVAILABLE


def public_dependency_inventory(graph: DependencyGraph) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for node_id, node in sorted(graph.nodes.items()):
        if node.kind not in {"service", "host"}:
            continue
        inventory.append(
            {
                "node_id": node_id,
                "kind": node.kind,
                "ref": node.ref,
                "depends_on": sorted(graph.dependencies.get(node_id, set())),
            }
        )
    return inventory
