from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path("/tmp/badlands_mission")
LOG = ROOT / "telemetry.jsonl"
FILES = ROOT / "files"
TICKETS = ROOT / "tickets.jsonl"
STATE = ROOT / "state.json"


DEFAULT_USERS = [
    "alice",
    "bob",
    "carol",
    "dave",
    "erin",
    "frank",
    "grace",
    "heidi",
    "ivan",
    "judy",
    "mallory",
    "oscar",
]


def _state() -> dict:
    if STATE.exists():
        return json.loads(STATE.read_text())
    return _initial_state()


def _save_state(state: dict) -> None:
    ROOT.mkdir(exist_ok=True)
    STATE.write_text(json.dumps(state, sort_keys=True))


def _initial_state(user_ids: list[str] | None = None, files: dict[str, str] | None = None) -> dict:
    users = {
        name: {"password": f"{name}-pw", "locked": False, "sessions": []}
        for name in (user_ids or DEFAULT_USERS)
    }
    return {
        "app_available": True,
        "isolated_hosts": [],
        "users": users,
        "session_counter": 0,
        "files": files or {"mission.txt": "mission package"},
        "mission_tasks": [],
        "tickets": [],
        "ticket_counter": 0,
    }


class Handler(BaseHTTPRequestHandler):
    def _log(self, event: dict) -> None:
        ROOT.mkdir(exist_ok=True)
        FILES.mkdir(exist_ok=True)
        event.setdefault("run_id", self.headers.get("X-Badlands-Run", "default"))
        event.setdefault("@timestamp", time.time())
        event.setdefault("event.dataset", "badlands.idp" if event.get("event.category") == "authentication" else "badlands.service")
        with LOG.open("a") as f:
            f.write(json.dumps(event, sort_keys=True) + "\n")

    def _service_log(
        self,
        *,
        action: str,
        user: str,
        host: str,
        service: str,
        outcome: str,
        reason: str,
        **extra: object,
    ) -> None:
        event = {
            "event.category": "service",
            "event.action": action,
            "event.outcome": outcome,
            "event.reason": reason,
            "user.name": user,
            "source.host": host,
            "destination.service": service,
            "service.name": service,
        }
        event.update({key: value for key, value in extra.items() if value is not None})
        self._log(event)

    def _json_body(self) -> dict:
        size = int(self.headers.get("Content-Length", "0"))
        if size <= 0:
            return {}
        return json.loads(self.rfile.read(size).decode() or "{}")

    def _idp_log(self, *, user: str, host: str, service: str, action: str, outcome: str, reason: str, session_id: str | None = None) -> None:
        event = {
            "event.category": "authentication",
            "event.action": action,
            "event.outcome": outcome,
            "event.reason": reason,
            "user.name": user,
            "source.host": host,
            "destination.service": service,
            "service.name": service,
        }
        if session_id:
            event["session.id"] = session_id
        self._log(event)

    def _session_ok(self, *, user: str, host: str, service: str, session_id: str) -> tuple[bool, str]:
        state = _state()
        record = state["users"].get(user, {})
        ok = bool(record) and not record.get("locked") and session_id in record.get("sessions", [])
        reason = "valid_session" if ok else ("account_locked" if record.get("locked") else "invalid_session")
        self._idp_log(
            user=user,
            host=host,
            service=service,
            action="session_validate",
            outcome="success" if ok else "failure",
            reason=reason,
            session_id=session_id or None,
        )
        return ok, reason

    def do_GET(self) -> None:
        user = self.headers.get("X-User", "anonymous")
        self._log(
            {
                "event.action": "http_request",
                "url.path": self.path,
                "user.name": user,
                "client.address": self.client_address[0],
            }
        )
        if self.path == "/health":
            state = _state()
            self.send_response(200 if state.get("app_available", True) else 503)
            self.end_headers()
            self.wfile.write(b"ok" if state.get("app_available", True) else b"isolated")
            return
        if self.path.startswith("/logs"):
            run_id = self.path.split("run_id=")[-1] if "run_id=" in self.path else None
            lines = []
            if LOG.exists():
                for line in LOG.read_text().splitlines():
                    if not run_id or f'"run_id": "{run_id}"' in line:
                        lines.append(line)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(("\n".join(lines) + ("\n" if lines else "")).encode())
            return
        if self.path.startswith("/file/"):
            session_id = self.headers.get("X-Session", "")
            host = self.headers.get("X-Host", "unknown")
            ok, reason = self._session_ok(user=user, host=host, service="file_share", session_id=session_id)
            if not ok:
                self._service_log(
                    action="file_read",
                    user=user,
                    host=host,
                    service="file_share",
                    outcome="failure",
                    reason=reason,
                    **{"file.name": self.path.split("/")[-1]},
                )
                self.send_response(403)
                self.end_headers()
                self.wfile.write(json.dumps({"ok": False, "reason": reason}).encode())
                return
            name = self.path.split("/")[-1]
            state = _state()
            content = state.get("files", {}).get(name)
            if content is None:
                self._service_log(
                    action="file_read",
                    user=user,
                    host=host,
                    service="file_share",
                    outcome="failure",
                    reason="file_not_found",
                    **{"file.name": name},
                )
                self.send_response(404)
                self.end_headers()
                self.wfile.write(json.dumps({"ok": False, "reason": "file_not_found"}).encode())
                return
            path = FILES / name
            if not path.exists():
                path.write_text(str(content))
            self._service_log(
                action="file_read",
                user=user,
                host=host,
                service="file_share",
                outcome="success",
                reason="valid_session",
                **{"file.name": name},
            )
            self.send_response(200)
            self.end_headers()
            self.wfile.write(path.read_bytes())
            return
        if self.path == "/tickets":
            state = _state()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"tickets": state.get("tickets", [])}).encode())
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"mission desk")

    def do_POST(self) -> None:
        user = self.headers.get("X-User", "anonymous")
        if self.path == "/admin/reset_state":
            body = self._json_body()
            ROOT.mkdir(exist_ok=True)
            FILES.mkdir(exist_ok=True)
            _save_state(_initial_state(body.get("users"), body.get("files")))
            LOG.write_text("")
            if TICKETS.exists():
                TICKETS.write_text("")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
            return
        if self.path == "/mission/task":
            body = self._json_body()
            task_id = body.get("task_id", "")
            host = body.get("host", "unknown")
            session_id = body.get("session_id", "")
            file_name = body.get("file", "mission.txt")
            state = _state()
            if body.get("precondition_failure"):
                reason = str(body["precondition_failure"])
                outcome = "failure"
                status = 409
            elif not state.get("app_available", True):
                reason = "service_isolated"
                outcome = "failure"
                status = 503
            else:
                ok, reason = self._session_ok(user=user, host=host, service="mission_app", session_id=session_id)
                if ok and file_name not in state.get("files", {}):
                    ok, reason = False, "file_not_found"
                outcome = "success" if ok else "failure"
                status = 200 if ok else 403
            record = {
                "task_id": task_id,
                "user": user,
                "host": host,
                "file": file_name,
                "status": "completed" if outcome == "success" else "failed",
                "reason": "mission_work_completed" if outcome == "success" else reason,
            }
            state.setdefault("mission_tasks", []).append(record)
            _save_state(state)
            self._service_log(
                action="mission_task",
                user=user,
                host=host,
                service="mission_app",
                outcome=outcome,
                reason=record["reason"],
                **{"badlands.task.id": task_id, "file.name": file_name},
            )
            self.send_response(status)
            self.end_headers()
            self.wfile.write(json.dumps({"ok": outcome == "success", **record}).encode())
            return
        if self.path == "/idp/login":
            body = self._json_body()
            state = _state()
            login_user = body.get("user", "")
            host = body.get("host", "unknown")
            password = body.get("password", "")
            record = state["users"].get(login_user)
            if not record:
                self._idp_log(user=login_user, host=host, service="idp", action="user_login", outcome="failure", reason="unknown_user")
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b'{"ok":false,"reason":"unknown_user"}')
                return
            if record.get("locked"):
                self._idp_log(user=login_user, host=host, service="idp", action="user_login", outcome="failure", reason="account_locked")
                self.send_response(423)
                self.end_headers()
                self.wfile.write(b'{"ok":false,"reason":"account_locked"}')
                return
            if password != record.get("password"):
                self._idp_log(user=login_user, host=host, service="idp", action="user_login", outcome="failure", reason="bad_password")
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b'{"ok":false,"reason":"bad_password"}')
                return
            state["session_counter"] = int(state.get("session_counter", 0)) + 1
            session_id = f"sess-{state['session_counter']:06d}"
            record.setdefault("sessions", []).append(session_id)
            _save_state(state)
            self._idp_log(user=login_user, host=host, service="idp", action="user_login", outcome="success", reason="password", session_id=session_id)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True, "session_id": session_id}).encode())
            return
        if self.path == "/idp/validate":
            body = self._json_body()
            state = _state()
            login_user = body.get("user", "")
            host = body.get("host", "unknown")
            session_id = body.get("session_id", "")
            record = state["users"].get(login_user, {})
            ok = not record.get("locked") and session_id in record.get("sessions", [])
            reason = "valid_session" if ok else ("account_locked" if record.get("locked") else "invalid_session")
            self._idp_log(user=login_user, host=host, service=body.get("service", "mission_app"), action="session_validate", outcome="success" if ok else "failure", reason=reason, session_id=session_id or None)
            self.send_response(200 if ok else 403)
            self.end_headers()
            self.wfile.write(json.dumps({"ok": ok, "reason": reason}).encode())
            return
        if self.path == "/idp/reset":
            body = self._json_body()
            state = _state()
            target = body.get("user", "")
            host = body.get("host", "defender")
            if target in state["users"]:
                state["users"][target]["locked"] = True
                state["users"][target]["sessions"] = []
                _save_state(state)
                self._idp_log(user=target, host=host, service="idp", action="account_reset", outcome="success", reason="defender_reset")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
                return
            self._idp_log(user=target, host=host, service="idp", action="account_reset", outcome="failure", reason="unknown_user")
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"ok":false,"reason":"unknown_user"}')
            return
        if self.path == "/idp/unlock":
            body = self._json_body()
            state = _state()
            target = body.get("user", "")
            host = body.get("host", "defender")
            if target in state["users"]:
                state["users"][target]["locked"] = False
                _save_state(state)
                self._idp_log(
                    user=target,
                    host=host,
                    service="idp",
                    action="account_unlock",
                    outcome="success",
                    reason="defender_rollback",
                )
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
                return
            self._idp_log(
                user=target,
                host=host,
                service="idp",
                action="account_unlock",
                outcome="failure",
                reason="unknown_user",
            )
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"ok":false,"reason":"unknown_user"}')
            return
        if self.path == "/idp/use_credential":
            body = self._json_body()
            state = _state()
            target = body.get("user", "")
            host = body.get("host", "attacker")
            record = state["users"].get(target)
            ok = bool(record) and not record.get("locked") and body.get("password") == record.get("password")
            reason = "credential_valid" if ok else ("account_locked" if record and record.get("locked") else "credential_invalid")
            self._idp_log(user=target, host=host, service=body.get("service", "files-1"), action="credential_use", outcome="success" if ok else "failure", reason=reason)
            self.send_response(200 if ok else 403)
            self.end_headers()
            self.wfile.write(json.dumps({"ok": ok, "reason": reason}).encode())
            return
        if self.path == "/admin/isolate_app":
            state = _state()
            state["app_available"] = False
            _save_state(state)
            self._log({"event.action": "service_isolated", "service.name": "mission_app", "user.name": user})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"isolated")
            return
        if self.path == "/admin/restore_app":
            state = _state()
            state["app_available"] = True
            _save_state(state)
            self._log({"event.action": "service_restored", "service.name": "mission_app", "user.name": user})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"restored")
            return
        if self.path == "/ticket":
            body = self._json_body()
            ROOT.mkdir(exist_ok=True)
            state = _state()
            state["ticket_counter"] = int(state.get("ticket_counter", 0)) + 1
            ticket = {
                "ticket_id": f"ticket-{state['ticket_counter']:06d}",
                "user": user,
                "host": body.get("host", "unknown"),
                "body": body.get("body", ""),
                "status": body.get("status", "open"),
                "reason": body.get("reason", body.get("body", "")),
                "task_id": body.get("task_id"),
            }
            state.setdefault("tickets", []).append(ticket)
            _save_state(state)
            with TICKETS.open("a") as f:
                f.write(json.dumps(ticket, sort_keys=True) + "\n")
            self._service_log(
                action="ticket_created",
                user=user,
                host=str(ticket["host"]),
                service="ticket",
                outcome="success",
                reason=str(ticket["reason"]),
                **{"badlands.ticket.id": ticket["ticket_id"], "badlands.task.id": ticket.get("task_id")},
            )
            self.send_response(201)
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True, **ticket}).encode())
            return
        if self.path == "/ticket/update":
            body = self._json_body()
            state = _state()
            ticket_id = body.get("ticket_id")
            for ticket in state.get("tickets", []):
                if ticket.get("ticket_id") == ticket_id:
                    ticket["status"] = body.get("status", ticket.get("status", "open"))
                    ticket["body"] = body.get("body", ticket.get("body", ""))
                    _save_state(state)
                    self._service_log(
                        action="ticket_updated",
                        user=user,
                        host=body.get("host", "unknown"),
                        service="ticket",
                        outcome="success",
                        reason=ticket["status"],
                        **{"badlands.ticket.id": ticket_id},
                    )
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(json.dumps({"ok": True, **ticket}).encode())
                    return
            self._service_log(
                action="ticket_updated",
                user=user,
                host=body.get("host", "unknown"),
                service="ticket",
                outcome="failure",
                reason="ticket_not_found",
                **{"badlands.ticket.id": ticket_id},
            )
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"ok":false,"reason":"ticket_not_found"}')
            return
        self.send_response(404)
        self.end_headers()


def main() -> None:
    ROOT.mkdir(exist_ok=True)
    FILES.mkdir(exist_ok=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()


if __name__ == "__main__":
    main()
