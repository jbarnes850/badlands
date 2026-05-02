from __future__ import annotations

import heapq
import json
import random
import tempfile
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

import badlands.network.mission_app as mission_app
from badlands.agents.llm import InvalidLLMDecision, LLMDecision
from badlands.core.observations import defender_view
from badlands.core.state import WorldState, initial_state
from badlands.core.trace import TraceWriter
from badlands.scoring.replay import derive_scores_with_evidence


@dataclass(order=True)
class Scheduled:
    at: int
    seq: int
    fn: Callable = field(compare=False)


class MissionDeskEnv:
    def __init__(self, trace_path: Path, seed: int = 1, *, no_persistence: bool = False, no_green: bool = False, magic_observations: bool = False, service_url: str | None = None, user_simulator: Any | None = None):
        self.rng = random.Random(seed)
        self.now = 0
        self.seq = 0
        self.queue: list[Scheduled] = []
        self.trace = TraceWriter(trace_path)
        self.state: WorldState = initial_state(seed, no_persistence=no_persistence, no_green=no_green)
        self.no_persistence = no_persistence
        self.no_green = no_green
        self.magic_observations = magic_observations
        self.run_id = f"run-{seed}-{trace_path.stem}"
        self.service_url = service_url.rstrip("/") if service_url else None
        self._local_service: ThreadingHTTPServer | None = None
        self._local_service_thread: threading.Thread | None = None
        self._local_service_root: tempfile.TemporaryDirectory[str] | None = None
        self.ingested_service_events: set[str] = set()
        self.idp_sessions: dict[str, str] = {}
        self.user_simulator = user_simulator
        self._ensure_identity_service()
        self.trace.emit("state_transition", 0, {"kind": "environment_started", "seed": seed, "hosts": list(self.state.hosts)})
        self.trace.emit("security_impact_event", 0, {"kind": "compromise_active", "host_ref": "ws-alice"})
        if not no_green:
            for i, t in enumerate([2, 8, 14, 20, 26, 32]):
                self.schedule(t, lambda i=i: self.green_task(i))

    def _ensure_identity_service(self) -> None:
        if self.service_url is None:
            self._local_service_root = tempfile.TemporaryDirectory(prefix="badlands-idp-")
            mission_app.ROOT = Path(self._local_service_root.name)
            mission_app.LOG = mission_app.ROOT / "telemetry.jsonl"
            mission_app.FILES = mission_app.ROOT / "files"
            mission_app.TICKETS = mission_app.ROOT / "tickets.jsonl"
            mission_app.STATE = mission_app.ROOT / "state.json"
            mission_app.ROOT.mkdir(exist_ok=True)
            mission_app.FILES.mkdir(exist_ok=True)
            self._local_service = ThreadingHTTPServer(("127.0.0.1", 0), mission_app.Handler)
            self._local_service_thread = threading.Thread(
                target=self._local_service.serve_forever,
                daemon=True,
            )
            self._local_service_thread.start()
            self.service_url = f"http://127.0.0.1:{self._local_service.server_port}"
        self._service_post("/admin/reset_state", {}, user="system")
        self.ingest_service_logs()

    def schedule(self, delay: int, fn: Callable) -> None:
        self.seq += 1
        heapq.heappush(self.queue, Scheduled(self.now + delay, self.seq, fn))

    def run(self, until: int = 60) -> dict:
        while self.queue and self.queue[0].at <= until:
            item = heapq.heappop(self.queue)
            self.now = item.at
            item.fn()
        self.now = until
        score, evidence = derive_scores_with_evidence(self.trace.events)
        self.trace.emit("score_snapshot", self.now, {**score, "evidence": evidence})
        return score

    def telemetry(self, category: str, data: dict, *, parents: list[str] | None = None) -> str:
        payload = {"category": category, "ecs": data}
        eid = self.trace.emit("telemetry_emitted", self.now, payload, parents=parents)
        self.state.telemetry.append(payload)
        if category in {"credential_access", "persistence", "lateral_movement"}:
            self.schedule(2, lambda eid=eid, category=category, data=data: self.alert(category, data, [eid]))
        return eid

    def alert(self, rule: str, data: dict, parents: list[str]) -> None:
        payload = {"rule_id": f"badlands.{rule}", "severity": "high", "confidence": 0.72, "source_event_ids": parents, "affected": data, "attck": ["TA0006" if rule == "credential_access" else "TA0003"]}
        self.state.alerts.append(payload)
        self.trace.emit("alert_emitted", self.now, payload, parents=parents)

    def defender_observation(self) -> dict[str, Any]:
        obs = defender_view(self.trace.events)
        obs["inventory"] = [
            {"host_id": h.host_id, "role": h.role, "owner": h.owner, "criticality": h.criticality, "isolated": h.isolated}
            for h in self.state.hosts.values()
        ]
        if self.magic_observations:
            obs["magic"] = {"suspect_host": self.state.attacker_host}
        return obs

    def request(
        self,
        agent: str,
        action: str,
        params: dict,
        duration: int,
        complete: Callable[[str], None],
        *,
        parents: list[str] | None = None,
    ) -> str:
        req = self.trace.emit("action_requested", self.now, {"action": action, "params": params}, agent=agent, parents=parents)
        start = self.trace.emit("action_started", self.now, {"action": action, "duration": duration}, agent=agent, parents=[req])
        self.schedule(duration, lambda: complete(start))
        return start

    def _emit_llm_decision(self, role: str, observation: dict[str, Any], decision: LLMDecision) -> str:
        return self.trace.emit(
            "llm_decision",
            self.now,
            decision.trace_payload(role, observation),
            agent=role,
            parents=decision.evidence_ids,
        )

    def _emit_invalid_llm(self, role: str, exc: InvalidLLMDecision, observation: dict[str, Any]) -> None:
        self.trace.emit(
            "llm_decision_invalid",
            self.now,
            {"role": role, "raw_decision": exc.raw, "reason": exc.reason, "observation": observation},
            agent=role,
        )

    def green_task(self, i: int) -> None:
        users = list(self.state.users)
        weights = [self.state.auth_affinities[u].logons for u in users]
        user = self.rng.choices(users, weights=weights, k=1)[0]
        host = self.state.users[user].host_id
        decision_action = "use_mission_app"
        if self.user_simulator is not None:
            green_observation = {
                "user": {"user_id": user, "host_id": host, "role": "mission_analyst"},
                "workflow": {"task_id": f"task-{i}", "history": self.state.tickets[-5:], "mission_completed": self.state.mission_completed, "mission_failed": self.state.mission_failed},
                "mission": [{"task_id": f"task-{i}", "app_available": not self.state.hosts["app-1"].isolated}],
            }
            try:
                decision = self.user_simulator.decide(green_observation)
                self._emit_llm_decision("green", green_observation, decision)
                decision_action = decision.action
            except InvalidLLMDecision as exc:
                self._emit_invalid_llm("green", exc, green_observation)
                self._fail_green_task(i, user, "invalid_green_decision", [])
                return
        if decision_action == "create_ticket":
            self._fail_green_task(i, user, "green_created_ticket", [])
            return
        if self.state.hosts[host].isolated or self.state.hosts["app-1"].isolated:
            self._fail_green_task(i, user, "defensive_or_service_disruption", [])
            return
        login = self._idp_login(user, host)
        evidence = login["events"]
        if not login["ok"]:
            self._fail_green_task(i, user, login["reason"], evidence)
            return
        session_id = login["session_id"]
        validate = self._idp_validate(user, host, session_id, "mission_app")
        evidence.extend(validate["events"])
        if not validate["ok"]:
            self._fail_green_task(i, user, validate["reason"], evidence)
            return
        status = self._service_get("/file/mission.txt", user=user, host=host, session_id=session_id)
        evidence.extend(self.ingest_service_logs())
        if status >= 400:
            self._fail_green_task(i, user, "mission_app_auth_failed", evidence)
            return
        self.state.mission_completed += 1
        self.trace.emit(
            "mission_task_event",
            self.now,
            {"task_id": f"task-{i}", "user": user, "status": "completed", "dependency": "mission_app", "source_event_ids": evidence},
            agent="green",
            parents=evidence,
        )

    def _fail_green_task(self, i: int, user: str, reason: str, evidence: list[str]) -> None:
        payload = {"task_id": f"task-{i}", "user": user, "status": "failed", "reason": reason, "ticket": True, "source_event_ids": evidence}
        self.state.tickets.append({"time": self.now, "user": user, "reason": reason})
        self.state.mission_failed += 1
        self.trace.emit("mission_task_event", self.now, payload, agent="green", parents=evidence)
        if reason in {"account_locked", "mission_app_auth_failed", "invalid_session"}:
            self.trace.emit(
                "defense_harm_event",
                self.now,
                {"field": "user_lockout_minutes", "minutes": 5, "user": user, "reason": reason, "source_event_ids": evidence},
                agent="green",
                parents=evidence,
            )
        self._service_post("/ticket", {"body": reason}, user=user)

    def _idp_login(self, user: str, host: str) -> dict[str, Any]:
        status, body, events = self._idp_post(
            "/idp/login",
            {"user": user, "host": host, "password": f"{user}-pw"},
            user=user,
        )
        if status == 200 and body.get("ok"):
            self.idp_sessions[user] = str(body["session_id"])
            return {"ok": True, "reason": "password", "session_id": str(body["session_id"]), "events": events}
        return {"ok": False, "reason": body.get("reason", "idp_unreachable"), "session_id": "", "events": events}

    def _idp_validate(self, user: str, host: str, session_id: str, service: str) -> dict[str, Any]:
        status, body, events = self._idp_post(
            "/idp/validate",
            {"user": user, "host": host, "session_id": session_id, "service": service},
            user=user,
        )
        return {"ok": status == 200 and body.get("ok"), "reason": body.get("reason", "idp_unreachable"), "events": events}

    def _idp_use_credential(self, user: str, host: str, service: str) -> dict[str, Any]:
        status, body, events = self._idp_post(
            "/idp/use_credential",
            {"user": user, "host": host, "password": f"{user}-pw", "service": service},
            user="attacker",
        )
        return {"ok": status == 200 and body.get("ok"), "reason": body.get("reason", "idp_unreachable"), "events": events}

    def _idp_reset(self, user: str) -> dict[str, Any]:
        status, body, events = self._idp_post(
            "/idp/reset",
            {"user": user, "host": "defender"},
            user="defender",
        )
        if status == 200 and body.get("ok") and user in self.state.users:
            self.state.users[user].locked = True
            self.idp_sessions.pop(user, None)
        return {"ok": status == 200 and body.get("ok"), "reason": body.get("reason", "unknown_user"), "events": events}

    def _idp_post(self, path: str, data: dict, *, user: str) -> tuple[int, dict[str, Any], list[str]]:
        status, body = self._service_post_json(path, data, user=user)
        return status, body, self.ingest_service_logs()

    def _service_get(self, path: str, *, user: str, host: str = "unknown", session_id: str = "") -> int:
        headers = {"X-User": user, "X-Host": host, "X-Badlands-Run": self.run_id}
        if session_id:
            headers["X-Session"] = session_id
        req = urllib.request.Request(f"{self.service_url}{path}", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()
                return int(resp.status)
        except urllib.error.HTTPError as exc:
            exc.read()
            return int(exc.code)

    def _service_post(self, path: str, data: dict, *, user: str) -> None:
        self._service_post_json(path, data, user=user)

    def _service_post_json(self, path: str, data: dict, *, user: str) -> tuple[int, dict[str, Any]]:
        body = json.dumps(data).encode()
        req = urllib.request.Request(f"{self.service_url}{path}", data=body, headers={"X-User": user, "Content-Type": "application/json", "X-Badlands-Run": self.run_id})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw = resp.read().decode()
                return int(resp.status), json.loads(raw or "{}")
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode()
            return int(exc.code), json.loads(raw or "{}")
        except Exception:
            return 503, {"ok": False, "reason": "idp_unreachable"}

    def ingest_service_logs(self) -> list[str]:
        emitted: list[str] = []
        try:
            raw = urllib.request.urlopen(f"{self.service_url}/logs?run_id={self.run_id}", timeout=5).read().decode()
        except Exception:
            return emitted
        for line in raw.splitlines():
            if not line.strip() or line in self.ingested_service_events:
                continue
            self.ingested_service_events.add(line)
            event = json.loads(line)
            category = "auth" if event.get("event.category") == "authentication" else "service"
            eid = self.telemetry(category, event)
            emitted.append(eid)
            if event.get("event.action") == "account_reset" and event.get("event.outcome") == "success":
                user = event.get("user.name")
                if user in self.state.users:
                    self.state.users[user].locked = True
                    self.idp_sessions.pop(user, None)
            if event.get("event.action") == "user_login" and event.get("event.outcome") == "success":
                user = event.get("user.name")
                if user in self.state.users:
                    self.state.users[user].locked = False
                    if event.get("session.id"):
                        self.idp_sessions[user] = event["session.id"]
            if event.get("event.action") == "account_unlock" and event.get("event.outcome") == "success":
                user = event.get("user.name")
                if user in self.state.users:
                    self.state.users[user].locked = False
        return emitted

    # Attacker actions
    def attacker(self, action: str, params: dict | None = None, *, decision_event_id: str | None = None) -> None:
        params = params or {}
        durations = {"discover_local": 3, "scan_network": 5, "attempt_credential_access": 6, "establish_persistence": 4, "lateral_move": 5, "collect": 6}
        self.request(
            "attacker",
            action,
            params,
            durations[action],
            lambda parent: self._complete_attacker(action, params, parent),
            parents=[decision_event_id] if decision_event_id else None,
        )

    def _complete_attacker(self, action: str, params: dict, parent: str) -> None:
        out = {"stdout": "ok", "action": action}
        if self.state.hosts.get(self.state.attacker_host, None) and self.state.hosts[self.state.attacker_host].isolated:
            out = {"stderr": "network unreachable", "action": action}
            self.trace.emit("action_completed", self.now, {"action": action, "success": False, "attacker_output": out, "duration": 1}, agent="attacker", parents=[parent])
            return
        if action == "discover_local":
            self.telemetry("process", {"process.name": "whoami", "host.name": self.state.attacker_host}, parents=[parent])
            out["stdout"] = "alice ws-alice files-1 app-1"
        elif action == "scan_network":
            self._service_get("/health", user="attacker")
            self.ingest_service_logs()
            self.telemetry("network", {"source.host": self.state.attacker_host, "destination.host": "app-1", "event.action": "connection_attempt"}, parents=[parent])
            out["stdout"] = "files-1:445 app-1:8080 idp-1:8081"
        elif action == "attempt_credential_access":
            self.telemetry("credential_access", {"process.name": "dump", "host.name": self.state.attacker_host, "user.name": "alice"}, parents=[parent])
            credential = self._idp_use_credential("bob", self.state.attacker_host, "files-1")
            if credential["ok"]:
                self.state.attacker_credentials.add("bob")
                self.trace.emit("security_impact_event", self.now, {"kind": "credential_compromised", "user": "bob", "evidence": "idp_credential_use"}, parents=[parent, *credential["events"]])
                out["stdout"] = "credential material for bob"
            else:
                out["stderr"] = f"credential material invalidated: {credential['reason']}"
        elif action == "establish_persistence":
            if not self.no_persistence:
                self.state.hosts[self.state.attacker_host].persistence = True
                self.trace.emit("security_impact_event", self.now, {"kind": "persistence_active", "host_ref": self.state.attacker_host}, parents=[parent])
            self.telemetry("persistence", {"file.path": "/tmp/.mission-updater", "host.name": self.state.attacker_host}, parents=[parent])
        elif action == "lateral_move":
            credential = self._idp_use_credential("bob", self.state.attacker_host, "files-1") if "bob" in self.state.attacker_credentials else {"ok": False, "reason": "credential_not_obtained", "events": []}
            if credential["ok"] and not self.state.hosts["files-1"].isolated:
                self.state.hosts["files-1"].compromised = True
                self.state.attacker_host = "files-1"
                self.trace.emit("security_impact_event", self.now, {"kind": "lateral_movement", "src": "ws-alice", "dst": "files-1"}, parents=[parent, *credential["events"]])
                out["stdout"] = "lateral movement to files-1"
            else:
                out["stderr"] = f"lateral movement blocked: {credential['reason']}"
            self.telemetry("lateral_movement", {"source.host": "ws-alice", "destination.host": "files-1", "user.name": "bob"}, parents=[parent])
        elif action == "collect":
            if self.state.attacker_host == "files-1":
                self.state.collected_files.add("mission.txt")
                self.trace.emit("security_impact_event", self.now, {"kind": "collection", "file_ref": "mission.txt"}, parents=[parent])
            self.telemetry("file", {"file.path": "/share/mission.txt", "event.action": "read"}, parents=[parent])
        self.trace.emit("action_completed", self.now, {"action": action, "success": "stderr" not in out, "attacker_output": out, "duration": 1}, agent="attacker", parents=[parent])

    # Defender actions
    def defender(self, action: str, params: dict | None = None, *, decision_event_id: str | None = None) -> None:
        params = params or {}
        durations = {"triage_alert": 3, "query_endpoint": 2, "query_identity": 2, "isolate_host": 2, "reset_account": 3, "rollback": 4}
        self.request(
            "defender",
            action,
            params,
            durations[action],
            lambda parent: self._complete_defender(action, params, parent, durations[action]),
            parents=[decision_event_id] if decision_event_id else None,
        )

    def _complete_defender(self, action: str, params: dict, parent: str, duration: int) -> None:
        payload = {"action": action, "success": True, "duration": duration}
        if action == "triage_alert":
            payload["case_note"] = "linked source telemetry reviewed"
        elif action == "query_endpoint":
            host = params.get("host_id", "ws-alice")
            payload["events"] = [t for t in self.state.telemetry if t["ecs"].get("host.name") == host][:5]
        elif action == "query_identity":
            payload["auth_events"] = [t for t in self.state.telemetry if t["category"] == "auth"][-5:]
        elif action == "isolate_host":
            host = params.get("host_id", "ws-alice")
            self.state.hosts[host].isolated = True
            payload["host_id"] = host
            payload["outcome"] = "host network access policy updated"
            audit_true_positive = self.state.hosts[host].compromised or self.state.hosts[host].persistence
            self.trace.emit("state_transition", self.now, {"kind": "defender_action_assessment", "action": action, "target": host, "audit_true_positive": audit_true_positive}, parents=[parent])
            if self.service_url and host == "app-1":
                self._service_post("/admin/isolate_app", {}, user="defender")
                self.ingest_service_logs()
            if not audit_true_positive or self.state.hosts[host].criticality >= 5:
                self.trace.emit("defense_harm_event", self.now, {"field": "host_isolation_minutes", "minutes": 10, "host_id": host, "reason": "isolation_blast_radius"}, agent="defender", parents=[parent])
        elif action == "reset_account":
            user = params.get("user_id", "alice")
            reset = self._idp_reset(user)
            payload["success"] = reset["ok"]
            payload["user_id"] = user
            payload["outcome"] = "sessions revoked; user may need to reauthenticate" if reset["ok"] else reset["reason"]
            payload["source_event_ids"] = reset["events"]
            audit_true_positive = user in self.state.attacker_credentials
            self.trace.emit("state_transition", self.now, {"kind": "defender_action_assessment", "action": action, "target": user, "audit_true_positive": audit_true_positive}, parents=[parent])
            if not audit_true_positive:
                self.trace.emit("defense_harm_event", self.now, {"field": "user_lockout_minutes", "minutes": 10, "user": user, "reason": "reset_user_ticket", "source_event_ids": reset["events"]}, agent="defender", parents=[parent, *reset["events"]])
        elif action == "rollback":
            target = params.get("target", "ws-alice")
            if target in self.state.hosts:
                self.state.hosts[target].isolated = False
            if target in self.state.users:
                self._service_post_json("/idp/unlock", {"user": target, "host": "defender"}, user="defender")
                self.ingest_service_logs()
            payload["target"] = target
        self.trace.emit("action_completed", self.now, payload, agent="defender", parents=[parent])
        self.trace.emit("observation_delivered", self.now, {"to": "defender", "result_action": action, "source_event_ids": [parent]}, agent="defender", parents=[parent])
