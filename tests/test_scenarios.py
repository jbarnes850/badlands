from __future__ import annotations

import json
from pathlib import Path

from badlands.core.env import MissionDeskEnv
from badlands.core.observations import assert_no_forbidden
from badlands.core.scenario import DEFAULT_SCENARIO_PATH, load_scenario
from badlands.core.state import initial_state


def _scenario_copy(tmp_path: Path, **updates) -> Path:
    data = json.loads(DEFAULT_SCENARIO_PATH.read_text())
    for key, value in updates.items():
        target = data
        parts = key.split(".")
        for part in parts[:-1]:
            target = target[part]
        target[parts[-1]] = value
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(data, sort_keys=True, indent=2))
    return path


def test_default_scenario_loads_deterministically():
    first = load_scenario()
    second = load_scenario()
    assert first == second
    assert first.scenario_id == "mission_desk_enclave"
    assert first.green_task_schedule == [2, 8, 14, 20, 26, 32, 44]
    assert first.auth_affinity_path.exists()
    assert {entry["taxonomy"] for entry in first.provenance}


def test_initial_state_is_fixture_driven(tmp_path: Path):
    scenario_path = _scenario_copy(
        tmp_path,
        hosts=[
            {"host_id": "ws-alice", "role": "workstation", "owner": "alice", "criticality": 4},
            {"host_id": "files-1", "role": "file_share", "owner": "svc-files", "criticality": 5, "files": {"mission.txt": "target package"}},
            {"host_id": "app-1", "role": "mission_app", "owner": "svc-app", "criticality": 5},
            {"host_id": "idp-1", "role": "identity", "owner": "svc-idp", "criticality": 5},
        ],
        users=[{"user_id": "alice", "primary_host": "ws-alice", "credentials_exposed": True}],
        services=[
            {"service_id": "idp", "host_id": "idp-1", "kind": "identity", "criticality": 5},
            {"service_id": "mission_app", "host_id": "app-1", "kind": "web_app", "criticality": 5},
            {"service_id": "file_share", "host_id": "files-1", "kind": "file_share", "criticality": 5},
        ],
        attacker={
            "initial_host": "ws-alice",
            "initial_credentials": ["alice"],
            "initial_compromised_hosts": ["ws-alice"],
            "credential_target_user": "alice",
            "lateral_target_host": "files-1",
            "collection_target": "mission.txt",
            "protected_assets": [
                {
                    "asset_id": "mission-package",
                    "file": "mission.txt",
                    "host_id": "files-1",
                    "service_id": "file_share",
                    "sensitivity": 5,
                    "mission_dependency": "use_mission_app",
                }
            ],
            "objectives": [
                {"objective_id": "collect-mission-package", "type": "collection", "asset_id": "mission-package"},
                {"objective_id": "exfiltrate-mission-package", "type": "exfiltration", "asset_id": "mission-package"},
                {"objective_id": "disrupt-mission-app", "type": "disruption", "service_id": "mission_app"},
            ],
        },
        **{"mission.workflow_tasks": []},
        **{
            "mission.service_profiles": {
                "mission_app": {"base_latency": 1, "degraded_latency": 6, "degraded_mode": "latency"},
                "file_share": {"base_latency": 1, "degraded_latency": 5},
                "idp": {"base_latency": 1, "degraded_latency": 3},
            }
        },
        **{"benign_noise.events": []},
    )
    state = initial_state(seed=7, scenario=scenario_path)
    assert sorted(state.hosts) == ["app-1", "files-1", "idp-1", "ws-alice"]
    assert sorted(state.users) == ["alice"]
    assert state.hosts["ws-alice"].criticality == 4
    assert state.attacker_credentials == {"alice"}


def test_changing_green_task_schedule_changes_trace_behavior(tmp_path: Path):
    short_scenario = _scenario_copy(
        tmp_path,
        **{
            "mission.green_task_schedule": [2],
            "mission.workflow_tasks": [],
            "benign_noise.events": [],
        },
    )
    default_env = MissionDeskEnv(tmp_path / "default.jsonl", seed=7)
    assert default_env.run(40)["mission_tasks_completed"] == 6
    short_env = MissionDeskEnv(tmp_path / "short.jsonl", seed=7, scenario=short_scenario)
    assert short_env.run(40)["mission_tasks_completed"] == 1


def test_scan_banners_are_unique_by_host_port(tmp_path: Path):
    env = MissionDeskEnv(tmp_path / "scan.jsonl", seed=7)
    banners = [f"{host}:{port}" for host, port in env._service_banners()]
    assert banners == ["idp-1:8081", "app-1:8080", "files-1:445"]


def test_scenario_fixture_truth_does_not_leak_to_observations(tmp_path: Path):
    env = MissionDeskEnv(tmp_path / "obs.jsonl", seed=7)
    env.run(10)
    obs = env.defender_observation()
    assert_no_forbidden(obs)
    text = str(obs)
    assert "provenance" not in text
    assert "validation_plan" not in text
    assert "initial_compromised_hosts" not in text


def test_scenario_loads_noise_and_sensor_profiles():
    scenario = load_scenario()
    kinds = {item["kind"] for item in scenario.benign_noise["events"]}
    assert {"failed_auth_burst", "noisy_script", "file_access_burst", "service_health_blip", "ticket_spike"} <= kinds
    assert scenario.sensor_model["categories"]["credential_access"]["delay"] > 0
    assert scenario.sensor_model["categories"]["network"]["drop_rate"] > 0


def test_scenario_loads_mission_workflows_and_roles():
    scenario = load_scenario()
    roles = {user.get("role") for user in scenario.users}
    task_types = {task["task_type"] for task in scenario.workflow_tasks}
    assert {"mission_analyst", "mission_coordinator"} <= roles
    assert {"use_mission_app", "read_write_file", "submit_report", "retry_after_failure"} <= task_types
    assert [task["scheduled_at"] for task in scenario.workflow_tasks] == scenario.green_task_schedule


def test_scenario_validates_dependency_references(tmp_path: Path):
    bad_service = _scenario_copy(
        tmp_path,
        services=[
            {"service_id": "mission_app", "host_id": "app-1", "kind": "web_app", "criticality": 5, "depends_on": ["missing_service"]},
            {"service_id": "idp", "host_id": "idp-1", "kind": "identity", "criticality": 5},
            {"service_id": "file_share", "host_id": "files-1", "kind": "file_share", "criticality": 5},
            {"service_id": "ticket", "host_id": "app-1", "kind": "ticket_surface", "criticality": 3},
        ],
    )
    try:
        load_scenario(bad_service)
    except ValueError as exc:
        assert "depends_on unknown service" in str(exc)
    else:
        raise AssertionError("invalid service dependency was accepted")

    bad_mission = _scenario_copy(tmp_path, **{"mission.dependencies": {"use_mission_app": ["missing_host"]}})
    try:
        load_scenario(bad_mission)
    except ValueError as exc:
        assert "references unknown host/service" in str(exc)
    else:
        raise AssertionError("invalid mission dependency was accepted")


def test_scenario_validates_attacker_objective_references(tmp_path: Path):
    bad_asset = _scenario_copy(tmp_path, **{"attacker.protected_assets": [{"asset_id": "bad", "file": "mission.txt", "host_id": "missing", "service_id": "file_share"}]})
    try:
        load_scenario(bad_asset)
    except ValueError as exc:
        assert "protected asset bad references unknown host" in str(exc)
    else:
        raise AssertionError("invalid protected asset host was accepted")

    bad_objective = _scenario_copy(tmp_path, **{"attacker.objectives": [{"objective_id": "bad-exfil", "type": "exfiltration", "asset_id": "missing"}]})
    try:
        load_scenario(bad_objective)
    except ValueError as exc:
        assert "bad-exfil references unknown asset" in str(exc)
    else:
        raise AssertionError("invalid attacker objective asset was accepted")

    bad_file = _scenario_copy(tmp_path, **{"attacker.protected_assets": [{"asset_id": "missing-file", "file": "absent.txt", "host_id": "files-1", "service_id": "file_share"}]})
    try:
        load_scenario(bad_file)
    except ValueError as exc:
        assert "protected asset missing-file references unknown host file" in str(exc)
    else:
        raise AssertionError("invalid protected asset file was accepted")

    bad_workflow = _scenario_copy(
        tmp_path,
        **{
            "mission.workflow_tasks": [
                {"task_id": "wf-ok-1", "workflow_id": "bad", "task_type": "read_write_file", "scheduled_at": 1, "deadline_at": 2, "priority": 1, "required_role": "mission_analyst", "required_services": ["idp"], "required_files": []},
                {"task_id": "wf-ok-2", "workflow_id": "bad", "task_type": "submit_report", "scheduled_at": 2, "deadline_at": 3, "priority": 1, "required_role": "mission_coordinator", "required_services": ["idp"], "required_files": []},
                {"task_id": "wf-bad", "workflow_id": "bad", "task_type": "use_mission_app", "scheduled_at": 4, "deadline_at": 3, "priority": 1, "required_role": "mission_analyst", "required_services": ["idp"], "required_files": []},
            ]
        },
    )
    try:
        load_scenario(bad_workflow)
    except ValueError as exc:
        assert "wf-bad deadline must be at or after scheduled_at" in str(exc)
    else:
        raise AssertionError("invalid workflow deadline was accepted")

    bad_profile = _scenario_copy(tmp_path, **{"mission.service_profiles": {"mission_app": {"degraded_mode": "teleport"}}})
    try:
        load_scenario(bad_profile)
    except ValueError as exc:
        assert "mission_app.degraded_mode must be fail or latency" in str(exc)
    else:
        raise AssertionError("invalid service degraded_mode was accepted")
