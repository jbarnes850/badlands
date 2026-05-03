from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from openai import AsyncOpenAI

from agents import Agent, Runner, RunConfig, SQLiteSession
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel

from badlands.agents.llm import InvalidLLMDecision, OpenAICompatClient, REPAIR_PROMPT, _estimate_tokens


class AgentsSdkCompatClient:
    """OpenAI Agents SDK-backed JSON completion client for Badlands actors."""

    def __init__(
        self,
        *,
        role: str,
        base_url: str,
        api_key: str,
        model: str,
        session_id: str,
        session_db_path: Path,
        campaign_id: str,
        trace_id: str | None = None,
    ):
        self.role = role
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.session_id = session_id
        self.session_db_path = session_db_path
        self.campaign_id = campaign_id
        self.trace_id = trace_id
        self.last_completion_telemetry: dict[str, Any] = {}
        session_db_path.parent.mkdir(parents=True, exist_ok=True)
        self._openai = AsyncOpenAI(base_url=self.base_url, api_key=self.api_key)
        self._sdk_model = OpenAIChatCompletionsModel(model=self.model, openai_client=self._openai)
        self._session = SQLiteSession(session_id, db_path=str(session_db_path))

    def complete_json(
        self,
        messages: list[dict[str, str]],
        *,
        model: str | None = None,
        validator: Callable[[dict[str, Any]], None] | None = None,
        json_schema: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del json_schema
        return asyncio.run(self._complete_json(messages, model=model, validator=validator))

    async def _complete_json(
        self,
        messages: list[dict[str, str]],
        *,
        model: str | None,
        validator: Callable[[dict[str, Any]], None] | None,
    ) -> dict[str, Any]:
        last_error: Exception | None = None
        telemetry: dict[str, Any] = {
            "endpoint": self.base_url,
            "model": model or self.model,
            "sdk_mode": "direct_sdk",
            "sdk_run_id": None,
            "sdk_session_id": self.session_id,
            "sdk_session_db": str(self.session_db_path),
            "sdk_trace_group_id": self.campaign_id,
            "attempt_count": 0,
            "repair_count": 0,
            "prompt_token_estimate": _estimate_tokens(json.dumps(messages, sort_keys=True)),
            "completion_tokens": 0,
            "wall_latency_s": 0.0,
            "validation_error": None,
            "invalid_decision_reason": None,
            "raw_outputs": [],
            "initial_invalid_count": 0,
            "repairs_attempted": 0,
            "repair_invalid_count": 0,
            "final_invalid_count": 0,
            "parse_failures": 0,
        }
        started = time.perf_counter()
        repair_messages: list[dict[str, str]] | None = None
        for attempt in range(2):
            telemetry["attempt_count"] = attempt + 1
            sdk_run_id = f"{self.campaign_id}-{self.role}-{uuid.uuid4().hex[:12]}"
            telemetry["sdk_run_id"] = sdk_run_id
            active_messages = repair_messages or messages
            raw = await self._run_agent(active_messages, sdk_run_id=sdk_run_id)
            telemetry["raw_outputs"].append({"attempt": attempt + 1, "content": raw})
            telemetry["completion_tokens"] += _estimate_tokens(raw)
            try:
                parsed = OpenAICompatClient._parse_json(raw)
                if validator is not None:
                    validator(parsed)
                telemetry["wall_latency_s"] = round(time.perf_counter() - started, 6)
                self.last_completion_telemetry = telemetry
                return parsed
            except json.JSONDecodeError as exc:
                last_error = exc
                telemetry["validation_error"] = str(exc)
                telemetry["invalid_decision_reason"] = str(exc)
                telemetry["parse_failures"] += 1
                if attempt == 0:
                    telemetry["initial_invalid_count"] += 1
                    telemetry["repair_count"] += 1
                    telemetry["repairs_attempted"] += 1
                    repair_messages = [
                        {"role": "system", "content": REPAIR_PROMPT},
                        {"role": "user", "content": f"Repair this response:\n{raw}"},
                    ]
                else:
                    telemetry["repair_invalid_count"] += 1
                    telemetry["final_invalid_count"] += 1
            except InvalidLLMDecision as exc:
                telemetry["validation_error"] = exc.reason
                telemetry["invalid_decision_reason"] = exc.reason
                if attempt == 0:
                    telemetry["initial_invalid_count"] += 1
                else:
                    telemetry["repair_invalid_count"] += 1
                telemetry["final_invalid_count"] += 1
                telemetry["wall_latency_s"] = round(time.perf_counter() - started, 6)
                exc.telemetry = telemetry
                self.last_completion_telemetry = telemetry
                raise exc
            except ValueError as exc:
                last_error = exc
                telemetry["validation_error"] = str(exc)
                telemetry["invalid_decision_reason"] = str(exc)
                if attempt == 0:
                    telemetry["initial_invalid_count"] += 1
                else:
                    telemetry["repair_invalid_count"] += 1
                telemetry["final_invalid_count"] += 1
                telemetry["wall_latency_s"] = round(time.perf_counter() - started, 6)
                self.last_completion_telemetry = telemetry
                raise InvalidLLMDecision("unknown", {"raw_outputs": telemetry["raw_outputs"]}, str(exc), telemetry) from exc
        telemetry["wall_latency_s"] = round(time.perf_counter() - started, 6)
        telemetry["final_invalid_count"] = max(1, int(telemetry["final_invalid_count"]))
        self.last_completion_telemetry = telemetry
        raise InvalidLLMDecision(
            "unknown",
            {"raw_outputs": telemetry["raw_outputs"]},
            f"Agents SDK response did not return parseable JSON after retries: {last_error}",
            telemetry,
        )

    async def _run_agent(self, messages: list[dict[str, str]], *, sdk_run_id: str) -> str:
        instructions = messages[0]["content"] if messages else "Return JSON only."
        user_input = messages[-1]["content"] if messages else "{}"
        agent = Agent(
            name=f"Badlands {self.role}",
            instructions=instructions,
            model=self._sdk_model,
        )
        result = await Runner.run(
            agent,
            user_input,
            session=self._session,
            run_config=RunConfig(
                tracing_disabled=True,
                workflow_name="badlands-ds29-campaign",
                trace_id=self.trace_id,
                group_id=self.campaign_id,
                trace_metadata={
                    "badlands_campaign_id": self.campaign_id,
                    "badlands_role": self.role,
                    "badlands_sdk_run_id": sdk_run_id,
                    "badlands_sdk_session_id": self.session_id,
                },
            ),
        )
        return str(result.final_output)
