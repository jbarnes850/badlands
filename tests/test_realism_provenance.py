from __future__ import annotations

import re
from pathlib import Path

import pytest


REPORT = Path("docs/realism-provenance.md")

REQUIRED_SOURCES = {
    "ncsc": "https://www.ncsc.gov.uk/blogs/why-cyber-defenders-need-to-be-ready-for-frontier-ai",
    "arxiv": "https://arxiv.org/pdf/2604.08805v1",
    "optc": "https://github.com/FiveDirections/OpTC-data",
    "lanl-cyber1": "https://csr.lanl.gov/data/cyber1/",
    "lanl-data": "https://csr.lanl.gov/data/",
    "mordor-site": "https://mordordatasets.com/",
    "mordor-github": "https://github.com/OTRF/mordor",
    "caldera-site": "https://caldera.mitre.org/",
    "caldera-github": "https://github.com/mitre/caldera",
    "attack": "https://attack.mitre.org/",
    "ecs": "https://www.elastic.co/guide/en/ecs/current/index.html",
    "elastic-rules": "https://github.com/elastic/detection-rules",
    "sigma-site": "https://sigmahq.io/",
    "sigma-github": "https://github.com/SigmaHQ/sigma",
    "nist": "https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final",
    "cisa": "https://www.cisa.gov/news-events/news/incident-and-vulnerability-response-playbooks",
    "cyberwheel": "https://github.com/ORNL/cyberwheel",
    "cyborg": "https://github.com/cage-challenge/CybORG",
    "nasimemu": "https://github.com/jaromiru/NASimEmu",
}

REQUIRED_MECHANISMS = {
    "Scenario/world fixture",
    "Identity service",
    "Mission services and workflows",
    "Green behavior and benign noise",
    "Attacker actions and objectives",
    "Defender actions and case workflow",
    "Observation surfaces and sensors",
    "Timing and concurrency",
    "Scoring and replay evidence",
    "Validity ablations",
    "Live inference and model-output review",
    "Campaign/session memory",
    "Sim-to-emulation calibration hooks",
}

STALE_SOURCE_URLS = {
    "https://www.cisa.gov/resources-tools/resources/incident-response-playbook",
    "https://github.com/dfki-in-sec/NASimEmu",
}


pytestmark = pytest.mark.skipif(
    not REPORT.exists(),
    reason="internal realism provenance docs are not included in public release checkouts",
)


def _table_rows(text: str) -> list[list[str]]:
    rows = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or "---" in stripped or stripped.startswith("| Mechanism "):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) == 6:
            rows.append(cells)
    return rows


def test_realism_provenance_report_contains_required_source_pack() -> None:
    text = REPORT.read_text()
    missing = [name for name, url in REQUIRED_SOURCES.items() if url not in text]
    assert not missing


def test_realism_provenance_does_not_use_known_stale_source_urls() -> None:
    combined = "\n".join(
        path.read_text()
        for path in (REPORT, Path("docs/substrate-review.md"))
    )
    stale = [url for url in STALE_SOURCE_URLS if url in combined]
    assert not stale


def test_realism_provenance_covers_major_mechanisms_with_status_and_artifacts() -> None:
    rows = _table_rows(REPORT.read_text())
    by_mechanism = {row[0]: row for row in rows}
    assert REQUIRED_MECHANISMS <= set(by_mechanism)
    for mechanism in REQUIRED_MECHANISMS:
        row = by_mechanism[mechanism]
        status = row[1]
        assert status in {"implemented", "partial", "planned", "assumption"}
        assert row[3], f"{mechanism} missing source anchor"
        assert row[4] or row[5], f"{mechanism} needs local artifact or validation plan"


def test_realism_provenance_local_artifact_paths_exist() -> None:
    missing = []
    for row in _table_rows(REPORT.read_text()):
        for candidate in re.findall(r"`([^`]+)`", row[4]):
            path = Path(candidate)
            if not path.exists():
                missing.append(candidate)
    assert not missing


def test_realism_provenance_is_not_a_literature_dump() -> None:
    text = REPORT.read_text()
    words = re.findall(r"\b\w+\b", text)
    assert len(words) < 2200
    assert len(_table_rows(text)) <= 16
