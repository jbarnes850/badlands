from __future__ import annotations

import asyncio
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from openai import AsyncOpenAI
from openai.types.responses import ResponseTextDeltaEvent

from agents import Agent, Runner, RunConfig, SQLiteSession
from agents.memory.sqlite_session import SessionSettings
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel

from badlands.agents.llm import InvalidLLMDecision, OpenAICompatClient, REPAIR_PROMPT, _estimate_tokens


def _stream_text_delta(event: Any) -> str:
    if getattr(event, "type", None) != "raw_response_event":
        return ""
    data = getattr(event, "data", None)
    if isinstance(data, ResponseTextDeltaEvent):
        return data.delta or ""
    if getattr(data, "type", None) != "response.output_text.delta":
        return ""
    delta = getattr(data, "delta", None)
    return delta if isinstance(delta, str) else ""


def _parse_partial_decision(buffer: str) -> tuple[str | None, str]:
    action = None
    try:
        action_match = re.search(r'"action"\s*:\s*"([a-zA-Z0-9_]+)"', buffer)
        if action_match:
            action = action_match.group(1)
        rationale_match = re.search(r'"rationale"\s*:\s*"((?:[^"\\]|\\.)*)', buffer)
        rationale = rationale_match.group(1) if rationale_match else buffer[-240:]
    except Exception:
        rationale = buffer[-240:]
    return action, rationale


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
        session_item_limit: int | None = None,
        session_context_limit_tokens: int | None = None,
        session_compaction_ratio: float = 0.85,
        session_hard_stop_ratio: float = 0.95,
        session_compaction_keep_recent_items: int = 24,
    ):
        self.role = role
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.session_id = session_id
        self.session_db_path = session_db_path
        self.campaign_id = campaign_id
        self.trace_id = trace_id
        self.session_item_limit = session_item_limit
        self.session_context_limit_tokens = session_context_limit_tokens
        self.session_compaction_ratio = session_compaction_ratio
        self.session_hard_stop_ratio = session_hard_stop_ratio
        self.session_compaction_keep_recent_items = max(2, session_compaction_keep_recent_items)
        self.last_completion_telemetry: dict[str, Any] = {}
        self.in_flight_dir = session_db_path.parent / "in-flight"
        session_db_path.parent.mkdir(parents=True, exist_ok=True)
        self._openai = AsyncOpenAI(base_url=self.base_url, api_key=self.api_key)
        self._sdk_model = OpenAIChatCompletionsModel(model=self.model, openai_client=self._openai)
        self._session = SQLiteSession(
            session_id,
            db_path=str(session_db_path),
            session_settings=SessionSettings(limit=session_item_limit),
        )

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
            "sdk_session_item_limit": self.session_item_limit,
            "sdk_session_strategy": self.session_strategy(),
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
            "sdk_session_context_before": None,
            "sdk_session_context_for_model": None,
            "sdk_session_context_after": None,
            "sdk_session_compaction": None,
        }
        started = time.perf_counter()
        repair_messages: list[dict[str, str]] | None = None
        for attempt in range(2):
            telemetry["attempt_count"] = attempt + 1
            sdk_run_id = f"{self.campaign_id}-{self.role}-{uuid.uuid4().hex[:12]}"
            telemetry["sdk_run_id"] = sdk_run_id
            active_messages = repair_messages or messages
            raw, session_telemetry = await self._run_agent(active_messages, sdk_run_id=sdk_run_id)
            telemetry["sdk_session_context_before"] = session_telemetry.get("before")
            telemetry["sdk_session_context_after"] = session_telemetry.get("after")
            telemetry["sdk_session_context_for_model"] = session_telemetry.get("for_model")
            telemetry["sdk_session_compaction"] = session_telemetry.get("compaction")
            context_for_model = session_telemetry.get("for_model") or {}
            telemetry["prompt_token_estimate"] = int(context_for_model.get("token_estimate") or 0) + _estimate_tokens(
                json.dumps(active_messages, sort_keys=True)
            )
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

    def session_strategy(self) -> dict[str, Any]:
        return {
            "mode": "openai_agents_sdk_sqlite_session",
            "item_limit": self.session_item_limit,
            "history_retrieval": "all_items" if self.session_item_limit is None else "latest_items",
            "context_limit_tokens": self.session_context_limit_tokens,
            "compaction_mode": "sdk_session_evidence_preserving_summary",
            "compaction_ratio": self.session_compaction_ratio,
            "hard_stop_ratio": self.session_hard_stop_ratio,
            "compaction_keep_recent_items": self.session_compaction_keep_recent_items,
            "session_primitives": ["SQLiteSession.get_items", "SQLiteSession.clear_session", "SQLiteSession.add_items"],
            "long_term_memory_source": "role-isolated OpenAI Agents SDK SQLiteSession raw transcript",
        }

    async def _run_agent(self, messages: list[dict[str, str]], *, sdk_run_id: str) -> tuple[str, dict[str, Any]]:
        instructions = messages[0]["content"] if messages else "Return JSON only."
        user_input = messages[-1]["content"] if messages else "{}"
        before, compaction = await self._compact_session_if_needed()
        for_model = await self._session_pressure()
        agent = Agent(
            name=f"Badlands {self.role}",
            instructions=instructions,
            model=self._sdk_model,
        )
        run_config = RunConfig(
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
        )
        partial_path = self.in_flight_dir / f"{self.role}.json"
        started_epoch = time.time()
        event_id = f"inflight:{self.role}:{int(started_epoch * 1000)}"
        prompt_tokens = int(for_model.get("token_estimate") or 0) + _estimate_tokens(json.dumps(messages, sort_keys=True))
        buffer: list[str] = []
        last_write = 0.0
        last_tokens = 0
        try:
            self._write_in_flight(
                partial_path,
                role=self.role,
                episode=self._current_episode(),
                event_id=event_id,
                started_at_epoch=started_epoch,
                updated_at_epoch=started_epoch,
                prompt_tokens=prompt_tokens,
                completion_tokens=0,
                partial_content="",
            )
            last_write = started_epoch
            stream = Runner.run_streamed(
                agent,
                user_input,
                session=self._session,
                run_config=run_config,
            )
            async for event in stream.stream_events():
                delta = _stream_text_delta(event)
                if not delta:
                    continue
                buffer.append(delta)
                content = "".join(buffer)
                now = time.time()
                completion_tokens = _estimate_tokens(content)
                if now - last_write >= 0.25 or completion_tokens - last_tokens >= 32:
                    self._write_in_flight(
                        partial_path,
                        role=self.role,
                        episode=self._current_episode(),
                        event_id=event_id,
                        started_at_epoch=started_epoch,
                        updated_at_epoch=now,
                        prompt_tokens=prompt_tokens,
                        completion_tokens=completion_tokens,
                        partial_content=content,
                    )
                    last_write = now
                    last_tokens = completion_tokens
            raw = str(stream.final_output)
            if raw:
                now = time.time()
                self._write_in_flight(
                    partial_path,
                    role=self.role,
                    episode=self._current_episode(),
                    event_id=event_id,
                    started_at_epoch=started_epoch,
                    updated_at_epoch=now,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=_estimate_tokens(raw),
                    partial_content=raw,
                )
        finally:
            try:
                partial_path.unlink()
            except FileNotFoundError:
                pass
        after = await self._session_pressure()
        return raw, {"before": before, "for_model": for_model, "after": after, "compaction": compaction}

    def _current_episode(self) -> int:
        best = 0
        for pattern in ("episode-*.jsonl", "step-*.jsonl"):
            for path in self.session_db_path.parent.glob(pattern):
                try:
                    best = max(best, int(path.stem.split("-")[1]))
                except Exception:
                    continue
        return best

    def _write_in_flight(
        self,
        path: Path,
        *,
        role: str,
        episode: int,
        event_id: str,
        started_at_epoch: float,
        updated_at_epoch: float,
        prompt_tokens: int,
        completion_tokens: int,
        partial_content: str,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        partial_action, partial_rationale = _parse_partial_decision(partial_content)
        payload = {
            "role": role,
            "episode": episode,
            "event_id": event_id,
            "started_at_epoch": started_at_epoch,
            "updated_at_epoch": updated_at_epoch,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "partial_content": partial_content,
            "partial_action": partial_action,
            "partial_rationale": partial_rationale,
            "in_flight": True,
            "endpoint": self.base_url,
            "model": self.model,
        }
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True))
        os.replace(tmp, path)

    async def _session_pressure(self) -> dict[str, Any]:
        items = await self._session.get_items(limit=None)
        token_estimate = _estimate_tokens(json.dumps(items, sort_keys=True))
        context_limit = self.session_context_limit_tokens
        pressure = round(token_estimate / context_limit, 6) if context_limit else None
        return {
            "item_count": len(items),
            "token_estimate": token_estimate,
            "context_limit_tokens": context_limit,
            "pressure": pressure,
        }

    async def _compact_session_if_needed(self) -> tuple[dict[str, Any], dict[str, Any] | None]:
        before = await self._session_pressure()
        context_limit = self.session_context_limit_tokens
        pressure = before.get("pressure")
        if context_limit is None or pressure is None or pressure < self.session_compaction_ratio:
            return before, None
        items = await self._session.get_items(limit=None)
        head_count = min(1, len(items))
        tail_count = min(self.session_compaction_keep_recent_items, max(0, len(items) - head_count))
        tail_start = len(items) - tail_count
        middle = items[head_count:tail_start]
        if not middle:
            if pressure >= self.session_hard_stop_ratio:
                raise RuntimeError(
                    f"{self.role} SDK session pressure {pressure:.3f} exceeds hard stop "
                    "without compactable middle history"
                )
            return before, None

        summary = self._summarize_session_items(middle)
        compacted_items = (
            items[:head_count]
            + [
                {
                    "role": "user",
                    "content": "Summarize the prior Badlands role-visible trajectory.",
                },
                {"role": "assistant", "content": summary},
            ]
            + items[tail_start:]
        )
        await self._session.clear_session()
        await self._session.add_items(compacted_items)
        after = await self._session_pressure()
        after_pressure = after.get("pressure")
        if after_pressure is not None and after_pressure >= self.session_hard_stop_ratio:
            raise RuntimeError(
                f"{self.role} SDK session remained above hard-stop pressure after compaction: "
                f"{after_pressure:.3f}"
            )
        return before, {
            "role": self.role,
            "mode": "sdk_session_evidence_preserving_summary",
            "token_before": before["token_estimate"],
            "token_after": after["token_estimate"],
            "pressure_before": before["pressure"],
            "pressure_after": after["pressure"],
            "item_count_before": before["item_count"],
            "item_count_after": after["item_count"],
            "compacted_item_count": len(middle),
            "preserved_head_count": head_count,
            "preserved_recent_count": tail_count,
            "summary": summary,
        }

    def _summarize_session_items(self, items: list[dict[str, Any]]) -> str:
        decisions: list[str] = []
        observation_ids: set[str] = set()
        decision_ids: set[str] = set()
        for item in items:
            content = _item_content_text(item)
            parsed = _parse_json_maybe(content)
            if isinstance(parsed, dict):
                observation_ids.update(str(eid) for eid in parsed.get("observation_event_ids", []) if isinstance(eid, str))
                evidence_ids = parsed.get("evidence_ids")
                if isinstance(evidence_ids, list):
                    decision_ids.update(str(eid) for eid in evidence_ids if isinstance(eid, str))
                action = parsed.get("action")
                if isinstance(action, str):
                    intent = str(parsed.get("intent") or parsed.get("rationale") or "")[:180]
                    decisions.append(f"{action}: {intent}".strip())
        summary = {
            "summary_type": "badlands_sdk_session_compaction",
            "role": self.role,
            "source": "role-visible SDK session transcript only",
            "compacted_items": len(items),
            "visible_observation_event_ids": sorted(observation_ids)[-80:],
            "cited_decision_evidence_ids": sorted(decision_ids)[-80:],
            "recent_decisions": decisions[-20:],
            "constraints": [
                "No hidden state, scorer truth, future schedule, or cross-role memory was used.",
                "Continue from this summary plus the recent raw transcript tail.",
                "Treat missing details as unknown rather than inventing evidence.",
            ],
        }
        return json.dumps(summary, sort_keys=True)


def _item_content_text(item: dict[str, Any]) -> str:
    content = item.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict):
                text = part.get("text") or part.get("content")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)
    return json.dumps(item, sort_keys=True)


def _parse_json_maybe(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
