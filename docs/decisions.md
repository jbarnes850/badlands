# Decision Log

Record architectural decisions that prevent future agents from re-litigating
scope. Keep entries short, dated, and linked to Linear when possible.

## 2026-05-02: Environment validity before agent sophistication

Badlands starts by proving the world is valid: active services, traceable
mission value, user activity, dependency effects, delayed actions, and
replayable scoring. Long-horizon agents are not useful until the environment
can expose mission-relevant failure modes.

Links: DS-15, DS-16, DS-17, DS-18, DS-20, DS-21, DS-22, DS-28.

## 2026-05-02: Badlands JSONL trace is canonical

The JSONL trace is the source of truth for world state, replay, and scoring.
External service logs, SDK traces, caches, and model-provider logs are
observability/correlation artifacts unless mirrored into Badlands trace as
role-visible evidence.

Links: DS-19, DS-24, DS-29.

## 2026-05-02: Live model brittleness is measurement signal

Invalid LLM decisions, malformed JSON, invented evidence ids, repeated actions,
and brittle role behavior must be preserved in trace/report artifacts. Do not
silently coerce invalid model behavior into valid environment actions.

Links: DS-19, DS-24, DS-27.

## 2026-05-02: DS-24 stays a thin harness

The live actor loop should be simple: build role-valid observation, call model,
validate decision, trace valid/invalid result, submit valid action, advance
environment deterministically. DS-24 must not become a custom agent framework.

Links: DS-24, DS-29.

## 2026-05-02: OpenAI Agents SDK owns campaign continuity

Durable actor memory, session continuity, compaction, resumable runs, and
future campaign state belong to DS-29 and should use the OpenAI Agents SDK
where possible. Earlier issues should emit telemetry and correlation ids, not
rebuild SDK primitives.

Links: DS-29.

## 2026-05-03: Long-horizon research ladder

The downstream research epic is 1-hour liveness, 3-hour continuity, 6-hour
co-evolution, and capability curves over tokens, time, model, harness, memory,
and scenario complexity. A run is not evidence merely because agents ran; it
must show trace-backed strategy, risk, mission, cost, latency, and disruption
changes.

Links: Badlands: Long-Horizon Co-Evolution and Capability Curves, DS-23,
DS-24, DS-29.

## 2026-05-03: Co-evolution is memory-mediated for the current lane

For the current Badlands environment and DS-29 campaign work, co-evolution
means within-run adaptation through role memory and across-episode adaptation
through campaign state.

Out of scope for this lane: prompt/scaffold self-modification, tool invention,
arbitrary shell access, scenario mutation by agents, or policy training from
prior traces.

Rationale: this keeps the first capability-curve experiments comparable. It
lets Badlands test whether role-visible memory and campaign state change
attacker/defender behavior without silently changing the harness.

Links: `docs/capability-curve-contract.md`, DS-29, long-horizon epic.

## 2026-05-03: Served context is a measured capability axis

Served context length must be recorded by role and treated as a
capability-curve variable. The existing 32K Spark profile is acceptable for
smoke and liveness validation, but DS-29 and longer campaign runs must increase
served context before claiming representative long-horizon evidence.

Rationale: role memory, SDK session continuity, trace summaries, and campaign
state can quickly consume short contexts. Comparing a 32K run to a larger
context run without declaring `served_context` as the comparison axis would mix
memory/harness effects with model and scenario effects.

Links: `docs/dgx-spark-live-inference.md`,
`docs/capability-curve-contract.md`, DS-29.
