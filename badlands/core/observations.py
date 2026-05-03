from __future__ import annotations

FORBIDDEN = {
    "host_compromised",
    "compromised",
    "attacker_location",
    "credential_stolen",
    "credentials_exposed",
    "true_positive",
    "false_positive",
    "scoring",
    "score",
    "objective_state",
    "hidden_label",
}


def assert_no_forbidden(obj: object) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in FORBIDDEN:
                raise AssertionError(f"forbidden observation field leaked: {k}")
            assert_no_forbidden(v)
    elif isinstance(obj, list):
        for item in obj:
            assert_no_forbidden(item)


def _visible_by_sensor(payload: dict, now: int | None) -> bool:
    sensor = payload.get("sensor", {})
    if sensor.get("dropped") or sensor.get("covered") is False:
        return False
    visible_at = sensor.get("visible_at")
    return now is None or visible_at is None or int(visible_at) <= now


def defender_view(events: list[dict], *, now: int | None = None) -> dict:
    visible_types = {"alert_emitted", "telemetry_emitted", "observation_delivered", "mission_task_event", "defense_harm_event"}
    obs = {"alerts": [], "telemetry": [], "tickets": [], "action_results": [], "service_health": []}
    for e in events:
        if now is not None and int(e["timestamp"]) > now:
            continue
        if e["type"] not in visible_types and e["agent"] != "defender":
            continue
        p = {**e["payload"], "event_id": e["event_id"]}
        if e["type"] == "alert_emitted":
            obs["alerts"].append(p)
        elif e["type"] == "telemetry_emitted":
            if not _visible_by_sensor(p, now):
                continue
            obs["telemetry"].append(p)
            ecs = p.get("ecs", {})
            if ecs.get("event.action") in {"ticket_created", "ticket_updated"}:
                obs["tickets"].append(
                    {
                        "event_id": e["event_id"],
                        "ticket_id": ecs.get("badlands.ticket.id"),
                        "user": ecs.get("user.name"),
                        "status": ecs.get("event.outcome"),
                        "reason": ecs.get("event.reason"),
                        "task_id": ecs.get("badlands.task.id"),
                        "source_event_ids": [e["event_id"]],
                    }
                )
        elif e["type"] == "mission_task_event" and p.get("ticket"):
            obs["tickets"].append(p)
        elif e["type"] == "action_completed" and e.get("agent") == "defender":
            obs["action_results"].append(p)
    assert_no_forbidden(obs)
    return obs


def attacker_view(events: list[dict]) -> dict:
    obs = {"results": []}
    for e in events:
        if e.get("agent") == "attacker" and e["type"] == "action_completed":
            obs["results"].append({**e["payload"].get("attacker_output", {}), "event_id": e["event_id"]})
    assert_no_forbidden(obs)
    return obs


def green_view(events: list[dict]) -> dict:
    obs = {"mission": [], "tickets": []}
    for e in events:
        if e["type"] == "mission_task_event":
            obs["mission"].append(
                {
                    "event_id": e["event_id"],
                    "task_id": e["payload"].get("task_id"),
                    "status": e["payload"].get("status"),
                    "reason": e["payload"].get("reason"),
                    "ticket": e["payload"].get("ticket", False),
                }
            )
        elif e["type"] == "defense_harm_event":
            obs["tickets"].append(
                {
                    "event_id": e["event_id"],
                    "reason": "mission_service_disruption"
                    if e["payload"].get("field") == "service_downtime_minutes"
                    else e["payload"].get("reason"),
                    "impact": e["payload"].get("field"),
                }
            )
    assert_no_forbidden(obs)
    return obs
