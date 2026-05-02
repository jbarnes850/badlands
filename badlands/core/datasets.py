from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

FIXTURE = Path(__file__).parents[1] / "datasets" / "lanl_auth_affinity_sample.csv"


@dataclass(frozen=True)
class AuthAffinity:
    user_id: str
    host_id: str
    logons: int
    anomalous_hosts: tuple[str, ...]


def load_auth_affinities(path: Path = FIXTURE) -> dict[str, AuthAffinity]:
    rows: dict[str, AuthAffinity] = {}
    with path.open() as f:
        for r in csv.DictReader(f):
            rows[r["user_id"]] = AuthAffinity(
                r["user_id"], r["primary_host"], int(r["logons"]), tuple(r["anomalous_hosts"].split(";"))
            )
    return rows
