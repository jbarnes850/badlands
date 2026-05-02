from __future__ import annotations

import os
import urllib.error
import urllib.request

import pytest

from badlands.agents.llm import AttackerLLM, DefenderLLM, GreenUserLLM, InvalidLLMDecision
from badlands.core.config import load_env

load_env()

pytestmark = pytest.mark.skipif(
    os.getenv("BADLANDS_RUN_LIVE_LLM_TESTS") != "1",
    reason="live Spark LLM opt-in only",
)


def _endpoint_available(url: str) -> bool:
    try:
        urllib.request.urlopen(f"{url.rstrip('/')}/models", timeout=2).read()
    except (OSError, urllib.error.URLError):
        return False
    return True


def test_live_green_defender_attacker_smoke(tmp_path):
    for cls, obs in [
        (GreenUserLLM, {"mission": [{"status": "app_available"}]}),
        (DefenderLLM, {"alerts": [{"rule_id": "badlands.credential_access", "severity": "high"}]}),
        (AttackerLLM, {"results": [{"stdout": "app-1:8080"}]}),
    ]:
        base_url = os.getenv(f"BADLANDS_{cls.role.upper()}_LLM_BASE_URL", "")
        if not _endpoint_available(base_url):
            pytest.skip(f"{cls.role} live LLM endpoint is not reachable: {base_url}")
        try:
            decision = cls(cache_dir=tmp_path, seed=1).decide(obs)
        except (InvalidLLMDecision, ValueError) as exc:
            pytest.skip(f"{cls.role} live LLM endpoint did not satisfy decision schema: {exc}")
        assert decision.action in cls.actions
