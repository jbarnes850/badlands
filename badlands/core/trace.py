from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SCHEMA_PATH = Path(__file__).parents[1] / "schemas" / "trace_event.schema.json"
VALIDATOR = Draft202012Validator(json.loads(SCHEMA_PATH.read_text()))
EVENT_TYPES = set(VALIDATOR.schema["properties"]["type"]["enum"])


@dataclass
class TraceWriter:
    path: Path
    counter: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("")

    def emit(
        self,
        event_type: str,
        timestamp: int,
        payload: dict[str, Any],
        *,
        agent: str | None = None,
        parents: list[str] | None = None,
    ) -> str:
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown event type {event_type}")
        self.counter += 1
        event = {
            "event_id": f"evt_{self.counter:06d}",
            "type": event_type,
            "timestamp": timestamp,
            "agent": agent,
            "parents": parents or [],
            "payload": payload,
        }
        VALIDATOR.validate(event)
        self.events.append(event)
        with self.path.open("a") as f:
            f.write(json.dumps(event, sort_keys=True) + "\n")
        return event["event_id"]


def load_trace(path: Path) -> list[dict[str, Any]]:
    events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    for event in events:
        VALIDATOR.validate(event)
    return events
