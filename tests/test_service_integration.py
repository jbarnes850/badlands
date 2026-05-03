from __future__ import annotations

import threading
from argparse import Namespace
from http.server import ThreadingHTTPServer
import urllib.error
import urllib.request

import badlands.network.mission_app as app
from badlands.cli import run_episode
from badlands.core.datasets import AuthAffinity
from badlands.core.dependencies import UNAVAILABLE
from badlands.core.env import MissionDeskEnv
from badlands.core.observations import defender_view
from badlands.core.state import User
from badlands.core.trace import load_trace
from badlands.scoring.replay import derive_scores


def test_episode_calls_service_and_ingests_logs(tmp_path):
    app.ROOT = tmp_path / "svc"
    app.LOG = app.ROOT / "telemetry.jsonl"
    app.FILES = app.ROOT / "files"
    app.TICKETS = app.ROOT / "tickets.jsonl"
    app.ROOT.mkdir()
    app.FILES.mkdir()
    server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        args = Namespace(trace=tmp_path / "trace.jsonl", seed=3, until=25, defender="evidence_gathering", no_persistence=False, no_green=False, magic_observations=False, service_url=url, llm_cache=tmp_path / "llm", green_actor="scripted", attacker_actor="scripted", defender_actor="baseline")
        run_episode(args)
        events = load_trace(tmp_path / "trace.jsonl")
        service = [e for e in events if e["type"] == "telemetry_emitted" and e["payload"].get("category") == "service"]
        assert service
        assert any(e["payload"]["ecs"].get("url.path") in {"/file/mission.txt", "/health"} for e in service)
    finally:
        server.shutdown()


def test_isolate_app_changes_authoritative_service_health(tmp_path):
    app.ROOT = tmp_path / "svc2"
    app.LOG = app.ROOT / "telemetry.jsonl"
    app.FILES = app.ROOT / "files"
    app.TICKETS = app.ROOT / "tickets.jsonl"
    app.STATE = app.ROOT / "state.json"
    app.ROOT.mkdir()
    app.FILES.mkdir()
    server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        urllib.request.urlopen(f"{url}/health", timeout=5).read()
        req = urllib.request.Request(f"{url}/admin/isolate_app", data=b"{}", headers={"X-Badlands-Run": "test"})
        try:
            urllib.request.urlopen(req, timeout=5).read()
        except ConnectionResetError:
            pass
        try:
            urllib.request.urlopen(f"{url}/health", timeout=5).read()
        except urllib.error.HTTPError as exc:
            assert exc.code == 503
        else:
            raise AssertionError("isolated service stayed healthy")
    finally:
        server.shutdown()


def test_defender_reset_changes_idp_state_and_blocks_green_auth(tmp_path):
    env = MissionDeskEnv(tmp_path / "reset.jsonl", seed=1, no_green=True)
    assert env._idp_login("alice", "ws-alice")["ok"]
    env.defender("reset_account", {"user_id": "alice"})
    env.run(10)
    blocked = env._idp_login("alice", "ws-alice")
    assert not blocked["ok"]
    assert blocked["reason"] == "account_locked"
    auth = [
        e["payload"]["ecs"]
        for e in load_trace(tmp_path / "reset.jsonl")
        if e["type"] == "telemetry_emitted" and e["payload"].get("category") == "auth"
    ]
    assert any(a["event.action"] == "account_reset" and a["user.name"] == "alice" for a in auth)
    assert any(a["event.action"] == "user_login" and a["event.reason"] == "account_locked" for a in auth)


def test_attacker_credential_and_lateral_depend_on_idp_state(tmp_path):
    allowed = MissionDeskEnv(tmp_path / "allowed.jsonl", seed=1, no_green=True)
    allowed.attacker("attempt_credential_access")
    allowed.schedule(7, lambda: allowed.attacker("lateral_move"))
    allowed.run(20)
    assert derive_scores(load_trace(tmp_path / "allowed.jsonl"))["lateral_movement_count"] == 1

    blocked = MissionDeskEnv(tmp_path / "blocked.jsonl", seed=1, no_green=True)
    blocked.defender("reset_account", {"user_id": "bob"})
    blocked.schedule(4, lambda: blocked.attacker("attempt_credential_access"))
    blocked.schedule(12, lambda: blocked.attacker("lateral_move"))
    blocked.run(25)
    events = load_trace(tmp_path / "blocked.jsonl")
    assert derive_scores(events)["lateral_movement_count"] == 0
    auth = [e["payload"]["ecs"] for e in events if e["type"] == "telemetry_emitted" and e["payload"].get("category") == "auth"]
    assert any(a["event.action"] == "credential_use" and a["event.reason"] == "account_locked" for a in auth)


def test_reset_race_blocks_in_flight_lateral_movement(tmp_path):
    reset_wins = MissionDeskEnv(tmp_path / "reset-wins.jsonl", seed=1, no_green=True)
    reset_wins.attacker("attempt_credential_access")
    reset_wins.run(7)
    reset_wins.attacker("lateral_move")
    reset_wins.defender("reset_account", {"user_id": "bob"})
    reset_wins.run(20)
    assert derive_scores(load_trace(tmp_path / "reset-wins.jsonl"))["lateral_movement_count"] == 0

    attacker_wins = MissionDeskEnv(tmp_path / "attacker-wins.jsonl", seed=1, no_green=True)
    attacker_wins.attacker("attempt_credential_access")
    attacker_wins.run(7)
    attacker_wins.attacker("lateral_move")
    attacker_wins.schedule(6, lambda: attacker_wins.defender("reset_account", {"user_id": "bob"}))
    attacker_wins.run(20)
    assert derive_scores(load_trace(tmp_path / "attacker-wins.jsonl"))["lateral_movement_count"] == 1


def test_green_lockout_failure_cites_idp_auth_evidence(tmp_path):
    env = MissionDeskEnv(tmp_path / "green-lockout.jsonl", seed=1, no_green=True)
    env.state.users = {"alice": User("alice", "ws-alice")}
    env.state.auth_affinities = {"alice": AuthAffinity("alice", "ws-alice", 1, ("idp-1",))}
    env.defender("reset_account", {"user_id": "alice"})
    env.schedule(4, lambda: env.green_task(0))
    env.run(10)
    events = load_trace(tmp_path / "green-lockout.jsonl")
    failed = [e for e in events if e["type"] == "mission_task_event" and e["payload"].get("status") == "failed"]
    assert failed
    assert failed[-1]["payload"]["reason"] == "account_locked"
    assert failed[-1]["payload"]["source_event_ids"]
    evidence_ids = set(failed[-1]["payload"]["source_event_ids"])
    evidence = [e for e in events if e["event_id"] in evidence_ids]
    assert any(e["payload"].get("category") == "auth" for e in evidence)


def test_identity_realism_changes_measured_security_risk(tmp_path):
    idp_valid = MissionDeskEnv(tmp_path / "idp-valid.jsonl", seed=1, no_green=True)
    idp_valid.attacker("attempt_credential_access")
    idp_valid.schedule(7, lambda: idp_valid.attacker("lateral_move"))
    valid_score = idp_valid.run(20)

    idp_invalidated = MissionDeskEnv(tmp_path / "idp-invalidated.jsonl", seed=1, no_green=True)
    idp_invalidated.defender("reset_account", {"user_id": "bob"})
    idp_invalidated.schedule(4, lambda: idp_invalidated.attacker("attempt_credential_access"))
    invalidated_score = idp_invalidated.run(20)

    assert valid_score["lateral_movement_count"] > invalidated_score["lateral_movement_count"]
    assert valid_score["overall_security_score"] < invalidated_score["overall_security_score"]


def test_green_mission_success_is_backed_by_service_logs(tmp_path):
    env = MissionDeskEnv(tmp_path / "mission-service.jsonl", seed=1, no_green=True)
    env.state.users = {"alice": User("alice", "ws-alice")}
    env.state.auth_affinities = {"alice": AuthAffinity("alice", "ws-alice", 1, ("idp-1",))}
    env.green_task(0)
    env.run(1)

    events = load_trace(tmp_path / "mission-service.jsonl")
    completed = [e for e in events if e["type"] == "mission_task_event" and e["payload"].get("status") == "completed"]
    assert completed
    evidence_ids = set(completed[-1]["payload"]["source_event_ids"])
    evidence = [e for e in events if e["event_id"] in evidence_ids]
    service_actions = {
        e["payload"]["ecs"].get("event.action")
        for e in evidence
        if e["type"] == "telemetry_emitted" and e["payload"].get("category") == "service"
    }
    assert {"file_read", "mission_task"} <= service_actions
    assert completed[-1]["parents"] == completed[-1]["payload"]["source_event_ids"]


def test_scenario_workflow_task_types_are_service_backed(tmp_path):
    env = MissionDeskEnv(tmp_path / "workflow-types.jsonl", seed=1, no_green=True)
    env.state.users = {
        "bob": User("bob", "ws-bob", "mission_analyst"),
        "erin": User("erin", "ws-erin", "mission_coordinator"),
    }
    env.state.auth_affinities = {
        "bob": AuthAffinity("bob", "ws-bob", 1, ("idp-1",)),
        "erin": AuthAffinity("erin", "ws-erin", 1, ("idp-1",)),
    }
    env.green_task(0)
    env.green_task(1)
    env.green_task(2)
    env.run(20)

    events = load_trace(tmp_path / "workflow-types.jsonl")
    mission_service = [
        e["payload"]["ecs"]
        for e in events
        if e["type"] == "telemetry_emitted"
        and e["payload"].get("category") == "service"
        and e["payload"]["ecs"].get("event.action") == "mission_task"
    ]
    assert {event["badlands.task.type"] for event in mission_service} >= {"use_mission_app", "read_write_file", "submit_report"}
    for event in mission_service:
        assert event["run_id"] == "run-1-workflow-types"
        assert event["user.name"]
        assert event["source.host"]
        assert event["badlands.task.id"]
        assert event["badlands.workflow.id"]
        assert event["service.name"] == "mission_app"
        assert "badlands.latency.minutes" in event
        assert "badlands.degraded" in event


def test_degraded_latency_can_cause_deadline_miss_with_trace_evidence(tmp_path):
    env = MissionDeskEnv(tmp_path / "deadline-miss.jsonl", seed=1, no_green=True)
    env.state.users = {"erin": User("erin", "ws-erin", "mission_coordinator")}
    env.state.auth_affinities = {"erin": AuthAffinity("erin", "ws-erin", 1, ("idp-1",))}
    env._set_dependency_state("service:mission_app", "degraded", "test_latency_deadline_pressure")
    env.schedule(14, lambda: env.green_task(2))
    score = env.run(30)
    events = load_trace(tmp_path / "deadline-miss.jsonl")
    failed = [e for e in events if e["type"] == "mission_task_event" and e["payload"].get("reason") == "deadline_missed"]
    assert failed
    assert score["deadline_minutes_lost"] > 0
    assert score["ticket_backlog_count"] > 0
    evidence = [e for e in events if e["event_id"] in set(failed[-1]["payload"]["source_event_ids"])]
    assert any(
        e["type"] == "telemetry_emitted"
        and e["payload"].get("category") == "service"
        and e["payload"]["ecs"].get("badlands.degraded") is True
        for e in evidence
    )


def test_file_workflow_does_not_require_mission_app_availability(tmp_path):
    env = MissionDeskEnv(tmp_path / "file-workflow-no-app.jsonl", seed=1, no_green=True)
    env.state.users = {"bob": User("bob", "ws-bob", "mission_analyst")}
    env.state.auth_affinities = {"bob": AuthAffinity("bob", "ws-bob", 1, ("idp-1",))}
    env._set_dependency_state("service:mission_app", UNAVAILABLE, "test_app_unavailable_for_file_workflow")
    env.green_task(1)
    score = env.run(20)
    events = load_trace(tmp_path / "file-workflow-no-app.jsonl")
    completed = [e for e in events if e["type"] == "mission_task_event" and e["payload"].get("task_id") == "wf-002"]
    assert completed[-1]["payload"]["status"] == "completed"
    assert completed[-1]["payload"]["task_type"] == "read_write_file"
    assert score["mission_tasks_completed"] == 1


def test_ticket_backlog_ignores_synthetic_ticket_spike_telemetry(tmp_path):
    env = MissionDeskEnv(tmp_path / "ticket-backlog.jsonl", seed=1, no_green=True)
    env.telemetry(
        "service",
        {
            "event.category": "service",
            "event.action": "ticket_created",
            "event.outcome": "success",
            "event.reason": "ticket_spike_summary",
        },
    )
    score = env.run(1)
    assert score["ticket_backlog_count"] == 0

    env = MissionDeskEnv(tmp_path / "real-ticket-backlog.jsonl", seed=1, no_green=True)
    env._create_ticket(user="alice", host="ws-alice", task_id="wf-test", reason="blocked", workflow_id="wf")
    score = env.run(1)
    assert score["ticket_backlog_count"] == 1


def test_file_access_requires_valid_idp_session(tmp_path):
    env = MissionDeskEnv(tmp_path / "file-session.jsonl", seed=1, no_green=True)
    assert env._service_get("/file/mission.txt", user="alice", host="ws-alice") == 403

    login = env._idp_login("alice", "ws-alice")
    assert login["ok"]
    assert env._service_get("/file/mission.txt", user="alice", host="ws-alice", session_id=login["session_id"]) == 200

    env.defender("reset_account", {"user_id": "alice"})
    env.run(5)
    assert env._service_get("/file/mission.txt", user="alice", host="ws-alice", session_id=login["session_id"]) == 403
    env.ingest_service_logs()
    auth = [
        e["payload"]["ecs"]
        for e in load_trace(tmp_path / "file-session.jsonl")
        if e["type"] == "telemetry_emitted" and e["payload"].get("category") == "auth"
    ]
    assert any(a["event.action"] == "session_validate" and a["event.reason"] == "invalid_session" for a in auth)
    assert any(a["event.action"] == "session_validate" and a["event.reason"] == "account_locked" for a in auth)


def test_ticket_creation_is_service_backed_and_defender_visible(tmp_path):
    env = MissionDeskEnv(tmp_path / "ticket-service.jsonl", seed=1, no_green=True)
    ticket = env._create_ticket(user="alice", host="ws-alice", task_id="task-99", reason="app confusing failure")
    assert ticket["ok"]

    events = load_trace(tmp_path / "ticket-service.jsonl")
    service_ticket = [
        e
        for e in events
        if e["type"] == "telemetry_emitted"
        and e["payload"].get("category") == "service"
        and e["payload"]["ecs"].get("event.action") == "ticket_created"
    ]
    assert service_ticket
    obs = defender_view(events)
    assert any(t.get("ticket_id") == ticket["ticket"]["ticket_id"] for t in obs["tickets"])
    assert "credentials_exposed" not in str(obs)


def test_mission_failure_requires_service_derived_evidence(tmp_path):
    env = MissionDeskEnv(tmp_path / "mission-failure-evidence.jsonl", seed=1, no_green=True)
    env.state.users = {"alice": User("alice", "ws-alice")}
    env.state.auth_affinities = {"alice": AuthAffinity("alice", "ws-alice", 1, ("idp-1",))}
    env.state.hosts[env.scenario.service_host(env.scenario.mission_service_id)].isolated = True
    env.green_task(0)
    env.run(1)

    events = load_trace(tmp_path / "mission-failure-evidence.jsonl")
    failed = [e for e in events if e["type"] == "mission_task_event" and e["payload"].get("status") == "failed"]
    assert failed
    evidence = [e for e in events if e["event_id"] in set(failed[-1]["payload"]["source_event_ids"])]
    assert any(
        e["payload"].get("category") == "service"
        and e["payload"]["ecs"].get("event.action") in {"mission_task", "ticket_created"}
        for e in evidence
    )
