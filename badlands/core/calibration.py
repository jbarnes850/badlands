from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from typing import Any

STATUSES = {"calibrated", "heuristic", "unvalidated"}
CONFIDENCES = {"low", "medium", "high"}


@dataclass(frozen=True)
class CalibrationRecord:
    id: str
    action: str
    source: tuple[str, ...]
    source_urls: tuple[str, ...]
    status: str
    preconditions: tuple[str, ...]
    expected_artifacts: tuple[str, ...]
    duration_range: tuple[int, int]
    success_notes: str
    failure_notes: str
    confidence: str

    @classmethod
    def from_mapping(cls, item: dict[str, Any]) -> "CalibrationRecord":
        required = {
            "id",
            "action",
            "source",
            "source_urls",
            "status",
            "preconditions",
            "expected_artifacts",
            "duration_range",
            "success_notes",
            "failure_notes",
            "confidence",
        }
        missing = required - set(item)
        if missing:
            raise ValueError(f"calibration record missing fields: {sorted(missing)}")
        duration = tuple(int(value) for value in item["duration_range"])
        if len(duration) != 2 or duration[0] > duration[1]:
            raise ValueError(f"invalid duration_range for {item['id']}")
        status = str(item["status"])
        confidence = str(item["confidence"])
        if status not in STATUSES:
            raise ValueError(f"invalid calibration status {status!r} for {item['id']}")
        if confidence not in CONFIDENCES:
            raise ValueError(f"invalid calibration confidence {confidence!r} for {item['id']}")
        return cls(
            id=str(item["id"]),
            action=str(item["action"]),
            source=tuple(str(value) for value in item["source"]),
            source_urls=tuple(str(value) for value in item["source_urls"]),
            status=status,
            preconditions=tuple(str(value) for value in item["preconditions"]),
            expected_artifacts=tuple(str(value) for value in item["expected_artifacts"]),
            duration_range=(duration[0], duration[1]),
            success_notes=str(item["success_notes"]),
            failure_notes=str(item["failure_notes"]),
            confidence=confidence,
        )

    def to_trace_metadata(self, applied_duration: int | None = None) -> dict[str, Any]:
        warnings: list[str] = []
        if self.status != "calibrated":
            warnings.append(f"{self.status}_calibration_not_validated")
        if applied_duration is not None:
            low, high = self.duration_range
            if not low <= applied_duration <= high:
                warnings.append("applied_duration_outside_calibration_range")
        return {
            "record_id": self.id,
            "status": self.status,
            "confidence": self.confidence,
            "source": list(self.source),
            "source_urls": list(self.source_urls),
            "preconditions": list(self.preconditions),
            "expected_artifacts": list(self.expected_artifacts),
            "duration_range": list(self.duration_range),
            "applied_duration": applied_duration,
            "duration_source": "existing_action_constant",
            "warnings": warnings,
        }


def _fixture_records() -> list[dict[str, Any]]:
    text = files("badlands.calibration").joinpath("action_calibration.json").read_text()
    return json.loads(text)


@lru_cache(maxsize=1)
def all_calibration_records() -> tuple[CalibrationRecord, ...]:
    records = tuple(CalibrationRecord.from_mapping(item) for item in _fixture_records())
    seen: set[str] = set()
    for record in records:
        if record.id in seen:
            raise ValueError(f"duplicate calibration id {record.id}")
        seen.add(record.id)
    return records


@lru_cache(maxsize=1)
def _records_by_action() -> dict[str, CalibrationRecord]:
    records: dict[str, CalibrationRecord] = {}
    for record in all_calibration_records():
        if record.action in records:
            raise ValueError(f"duplicate calibration action {record.action}")
        records[record.action] = record
    return records


def calibration_for_action(action: str) -> CalibrationRecord | None:
    return _records_by_action().get(action)


def calibration_metadata(action: str, applied_duration: int | None = None) -> dict[str, Any]:
    record = calibration_for_action(action)
    if record is not None:
        return record.to_trace_metadata(applied_duration=applied_duration)
    return {
        "record_id": None,
        "status": "unvalidated",
        "confidence": "low",
        "source": [],
        "source_urls": [],
        "preconditions": [],
        "expected_artifacts": [],
        "duration_range": None,
        "applied_duration": applied_duration,
        "duration_source": "existing_action_constant",
        "warnings": ["missing_calibration_record"],
    }


def calibration_report(actions: list[str] | tuple[str, ...]) -> dict[str, Any]:
    records = _records_by_action()
    missing = [action for action in actions if action not in records]
    return {
        "records": [record.to_trace_metadata() for record in records.values()],
        "missing": missing,
        "summary": {
            "actions_checked": len(actions),
            "records_found": len(actions) - len(missing),
            "records_missing": len(missing),
            "statuses": {
                status: sum(
                    1
                    for action in actions
                    if records.get(action, None) and records[action].status == status
                )
                for status in sorted(STATUSES)
            },
        },
    }
