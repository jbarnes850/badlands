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


def _state() -> dict:
    if STATE.exists():
        return json.loads(STATE.read_text())
    return _initial_state()


def _save_state(state: dict) -> None:
    ROOT.mkdir(exist_ok=True)
    STATE.write_text(json.dumps(state, sort_keys=True))


def _initial_state() -> dict:
    users = {
        name: {"password": f"{name}-pw", "locked": False, "sessions": []}
        for name in [
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
    }
    return {"app_available": True, "isolated_hosts": [], "users": users, "session_counter": 0}


class Handler(BaseHTTPRequestHandler):
    def _log(self, event: dict) -> None:
        ROOT.mkdir(exist_ok=True)
        FILES.mkdir(exist_ok=True)
        event.setdefault("run_id", self.headers.get("X-Badlands-Run", "default"))
        event.setdefault("@timestamp", time.time())
        event.setdefault("event.dataset", "badlands.idp" if event.get("event.category") == "authentication" else "badlands.service")
        with LOG.open("a") as f:
            f.write(json.dumps(event, sort_keys=True) + "\n")

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
            ok, reason = self._session_ok(user=user, host=host, service="mission_app", session_id=session_id)
            if not ok:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(json.dumps({"ok": False, "reason": reason}).encode())
                return
            name = self.path.split("/")[-1]
            path = FILES / name
            if not path.exists():
                path.write_text("mission package")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(path.read_bytes())
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"mission desk")

    def do_POST(self) -> None:
        user = self.headers.get("X-User", "anonymous")
        if self.path == "/admin/reset_state":
            ROOT.mkdir(exist_ok=True)
            FILES.mkdir(exist_ok=True)
            _save_state(_initial_state())
            LOG.write_text("")
            if TICKETS.exists():
                TICKETS.write_text("")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
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
            size = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(size).decode()
            ROOT.mkdir(exist_ok=True)
            with TICKETS.open("a") as f:
                f.write(json.dumps({"user": user, "body": body}) + "\n")
            self._log({"event.action": "ticket_created", "user.name": user})
            self.send_response(201)
            self.end_headers()
            self.wfile.write(b"created")
            return
        self.send_response(404)
        self.end_headers()


def main() -> None:
    ROOT.mkdir(exist_ok=True)
    FILES.mkdir(exist_ok=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()


if __name__ == "__main__":
    main()
