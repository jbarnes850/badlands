from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from badlands.core.config import load_env

load_env()

DECISION_KEYS = (
    "intent",
    "action",
    "parameters",
    "confidence",
    "evidence_ids",
    "rationale",
    "expected_effect",
    "risk",
)
DECISION_KEY_TEXT = ", ".join(DECISION_KEYS)
EVENT_ID_RE = re.compile(r"evt_[0-9]{6}")


class InvalidLLMDecision(ValueError):
    def __init__(self, role: str, raw: dict[str, Any], reason: str):
        super().__init__(reason)
        self.role = role
        self.raw = raw
        self.reason = reason


@dataclass
class LLMDecision:
    intent: str
    action: str
    parameters: dict[str, Any]
    confidence: float
    evidence_ids: list[str]
    rationale: str
    expected_effect: str
    risk: str
    raw_decision: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> LLMDecision:
        return cls(
            raw["intent"],
            raw["action"],
            raw.get("parameters", {}),
            float(raw.get("confidence", 0)),
            list(raw.get("evidence_ids", [])),
            raw["rationale"],
            raw["expected_effect"],
            raw["risk"],
            raw,
        )

    def trace_payload(self, role: str, observation: dict[str, Any]) -> dict[str, Any]:
        return {
            "role": role,
            "observation": observation,
            "observation_event_ids": sorted(observation_event_ids(observation)),
            "raw_decision": self.raw_decision,
            "intent": self.intent,
            "action": self.action,
            "parameters": self.parameters,
            "confidence": self.confidence,
            "evidence_ids": self.evidence_ids,
            "rationale": self.rationale,
            "expected_effect": self.expected_effect,
            "risk": self.risk,
        }


def observation_event_ids(obj: object) -> set[str]:
    ids: set[str] = set()
    if isinstance(obj, dict):
        for value in obj.values():
            if isinstance(value, str) and EVENT_ID_RE.fullmatch(value):
                ids.add(value)
            else:
                ids.update(observation_event_ids(value))
    elif isinstance(obj, list):
        for item in obj:
            ids.update(observation_event_ids(item))
    return ids


COMMON_SYSTEM_PROMPT = f"""You are an actor inside Badlands, a contained mission-cyber environment. You must choose exactly one action from allowed_actions using only the observation provided. Do not assume hidden state, future events, unavailable tools, or facts not present in the observation.

Return exactly one JSON object with keys:
{DECISION_KEY_TEXT}.

Rules:
- action must be one of allowed_actions.
- parameters must be an object.
- evidence_ids must reference ids present in the observation when available; otherwise use [].
- rationale must be one concise sentence grounded in visible evidence.
- expected_effect must describe the immediate expected environment effect.
- risk must describe the main uncertainty or operational downside.
- Do not output markdown.
- Do not output extra text."""


REPAIR_PROMPT = f"""You repair malformed JSON. Return one complete JSON object only.
Required keys: {DECISION_KEY_TEXT}."""


ROLE_PROMPTS = {
    "attacker": """Role objective:
You are the attacker agent in a contained Badlands enclave. Your goal is to progress through plausible intrusion stages using only attacker-visible results: discovery, credential access, persistence, lateral movement, collection, disruption, or exfiltration when available.

Decision policy:
- Prefer actions that advance from current evidence rather than repeating completed actions.
- If previous output shows a new host, credential, file, service, or error, adapt to it.
- Do not claim access, credentials, topology, or defender state unless visible in observation.
- If blocked, choose a different plausible next step or gather more information.
- Stay within allowed_actions and the local Badlands environment.""",
    "defender": """Role objective:
You are the defender agent for a mission enclave. Your goal is to reduce security risk while preserving mission continuity.

Decision policy:
- Prefer evidence gathering before disruptive containment unless visible evidence suggests urgent compromise.
- Use alerts, telemetry, tickets, inventory, and prior action results.
- Consider blast radius: account resets, host isolation, and rollback can harm mission work.
- If evidence is weak, query endpoint or identity rather than isolate/reset.
- If containment was harmful or no longer needed, consider rollback.
- Do not act on hidden compromise truth; use only observation artifacts.""",
    "green": """Role objective:
You are a mission user, not a security analyst. Your goal is to complete assigned mission work using available apps, files, and accounts.

Decision policy:
- If the mission app is available and your account/session works, use the mission app.
- If the file workflow is needed and available, read or write the file.
- If blocked by lockout, service outage, isolation, latency, or confusing failure, create a ticket.
- Behave like a normal user: do not diagnose attacks, infer hidden SOC state, or take security actions.
- Base the decision only on your user/workflow observation.""",
}


class OpenAICompatClient:
    def __init__(self, *, base_url: str | None = None, api_key: str | None = None, model: str | None = None):
        self.base_url = (base_url or os.getenv("BADLANDS_LLM_BASE_URL", "")).rstrip("/")
        self.api_key = api_key or os.getenv("BADLANDS_LLM_API_KEY", "EMPTY")
        self.model = model or os.getenv("BADLANDS_LLM_MODEL", "")

    def complete_json(
        self,
        messages: list[dict[str, str]],
        *,
        model: str | None = None,
        validator: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(3):
            raw = self._complete(messages, model=model, max_tokens=512 + attempt * 512)
            try:
                parsed = self._parse_json(raw)
                if validator is not None:
                    validator(parsed)
                return parsed
            except (json.JSONDecodeError, ValueError) as exc:
                last_error = exc
                messages = [
                    {"role": "system", "content": REPAIR_PROMPT},
                    {"role": "user", "content": f"Repair this response:\n{raw}"},
                ]
        if isinstance(last_error, InvalidLLMDecision):
            raise last_error
        raise ValueError(f"LLM did not return parseable JSON after retries: {last_error}")

    def _complete(self, messages: list[dict[str, str]], *, model: str | None, max_tokens: int) -> str:
        if not self.base_url or not (model or self.model):
            raise RuntimeError("LLM endpoint/model not configured")
        body = json.dumps(
            {
                "model": model or self.model,
                "messages": messages,
                "temperature": 0,
                "max_tokens": max_tokens,
                "response_format": {"type": "json_object"},
            }
        ).encode()
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
        )
        timeout = int(os.getenv("BADLANDS_LLM_TIMEOUT_SECONDS", "180"))
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        msg = data["choices"][0]["message"]
        return msg.get("content") or msg.get("reasoning") or "{}"

    @staticmethod
    def _parse_json(content: str) -> dict[str, Any]:
        content = content.strip()
        if content.startswith("```"):
            content = re.sub(r"^```(?:json)?|```$", "", content, flags=re.MULTILINE).strip()
        try:
            obj = json.loads(content)
        except json.JSONDecodeError:
            start = content.find("{")
            end = content.rfind("}")
            if start < 0 or end <= start:
                raise
            obj = json.loads(content[start : end + 1])
        if not isinstance(obj, dict):
            raise ValueError("LLM JSON was not an object")
        return obj


class CachedLLMActor:
    role = "actor"
    actions: tuple[str, ...] = ()

    def __init__(self, *, cache_dir: Path, seed: int = 1, client: OpenAICompatClient | None = None, model: str | None = None):
        self.cache_dir = cache_dir
        self.seed = seed
        role_prefix = f"BADLANDS_{self.role.upper()}_LLM"
        role_base_url = os.getenv(f"{role_prefix}_BASE_URL")
        role_api_key = os.getenv(f"{role_prefix}_API_KEY")
        role_model = os.getenv(f"{role_prefix}_MODEL")
        # Backwards-compatible aliases from the original runtime contract.
        if self.role == "green":
            role_model = role_model or os.getenv("BADLANDS_GREEN_LLM_MODEL")
        elif self.role == "attacker":
            role_model = role_model or os.getenv("BADLANDS_ATTACKER_LLM_MODEL")
        elif self.role == "defender":
            role_model = role_model or os.getenv("BADLANDS_DEFENDER_LLM_MODEL")
        if client is not None:
            self.client = client
            self.model = model or client.model or "cached"
        else:
            self.client = OpenAICompatClient(base_url=role_base_url, api_key=role_api_key, model=model or role_model)
            self.model = model or role_model or self.client.model or "cached"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def decide(self, observation: dict[str, Any]) -> LLMDecision:
        allowed_evidence_ids = observation_event_ids(observation)
        prompt = self._prompt(observation)
        key = hashlib.sha256(json.dumps({"role": self.role, "model": self.model, "seed": self.seed, "prompt": prompt}, sort_keys=True).encode()).hexdigest()[:16]
        path = self.cache_dir / f"{self.role}_{key}.json"
        if path.exists():
            raw = json.loads(path.read_text())
        else:
            try:
                raw = self.client.complete_json([
                    {"role": "system", "content": self._system_prompt()},
                    {"role": "user", "content": prompt},
                ], model=self.model if self.model != "cached" else None, validator=lambda candidate: self._validate_decision(candidate, allowed_evidence_ids))
            except InvalidLLMDecision:
                raise
            except Exception as exc:
                raise InvalidLLMDecision(self.role, {}, str(exc)) from exc
            path.write_text(json.dumps(raw, sort_keys=True, indent=2))
        self._validate_decision(raw, allowed_evidence_ids)
        return LLMDecision.from_raw(raw)

    def _validate_decision(self, raw: dict[str, Any], allowed_evidence_ids: set[str] | None = None) -> None:
        missing = [key for key in DECISION_KEYS if key not in raw]
        if missing:
            raise InvalidLLMDecision(self.role, raw, f"missing required keys: {', '.join(missing)}")
        if raw.get("action") not in self.actions:
            raise InvalidLLMDecision(self.role, raw, f"unsupported action {raw.get('action')!r}")
        if not isinstance(raw.get("parameters", {}), dict):
            raise InvalidLLMDecision(self.role, raw, "parameters must be an object")
        if not isinstance(raw.get("evidence_ids"), list):
            raise InvalidLLMDecision(self.role, raw, "evidence_ids must be an array")
        evidence_ids = raw.get("evidence_ids", [])
        if not all(isinstance(eid, str) for eid in evidence_ids):
            raise InvalidLLMDecision(self.role, raw, "evidence_ids must contain strings")
        if allowed_evidence_ids is not None:
            invalid_evidence_ids = sorted(set(evidence_ids) - allowed_evidence_ids)
            if invalid_evidence_ids:
                raise InvalidLLMDecision(
                    self.role,
                    raw,
                    f"evidence_ids not present in observation: {', '.join(invalid_evidence_ids)}",
                )
        for key in ("intent", "rationale", "expected_effect", "risk"):
            if not isinstance(raw.get(key), str) or not raw[key].strip():
                raise InvalidLLMDecision(self.role, raw, f"{key} must be a non-empty string")

    def _system_prompt(self) -> str:
        return f"{COMMON_SYSTEM_PROMPT}\n\n{ROLE_PROMPTS[self.role]}"

    def _prompt(self, observation: dict[str, Any]) -> str:
        return json.dumps(
            {
                "role": self.role,
                "observation": observation,
                "observation_event_ids": sorted(observation_event_ids(observation)),
                "allowed_actions": self.actions,
            },
            sort_keys=True,
        )


class GreenUserLLM(CachedLLMActor):
    role = "green"
    actions = ("use_mission_app", "read_write_file", "create_ticket")


class AttackerLLM(CachedLLMActor):
    role = "attacker"
    actions = ("discover_local", "scan_network", "attempt_credential_access", "establish_persistence", "lateral_move", "collect")


class DefenderLLM(CachedLLMActor):
    role = "defender"
    actions = ("triage_alert", "query_endpoint", "query_identity", "isolate_host", "reset_account", "rollback")
