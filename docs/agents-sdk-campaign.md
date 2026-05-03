# Agents SDK Campaign Harness

DS-29 adds a minimal two-step campaign harness for role-isolated continuity
experiments. It is a measurement harness, not a new environment authority.
Badlands JSONL remains canonical for replay and scoring.

## Source Grounding

- NCSC notes that frontier AI is changing the cost, speed, and scale of cyber
  operations for both attackers and defenders, and that defenders should use
  comparable capabilities to retain defensive advantage:
  <https://www.ncsc.gov.uk/blogs/why-cyber-defenders-need-to-be-ready-for-frontier-ai>
- `Building Better Environments for Autonomous Cyber Defence` describes
  simulation fidelity in terms of virtualisation and modelling gaps, including
  observation, action, sequence, and reward modelling:
  <https://arxiv.org/pdf/2604.08805v1>
- OpenAI's Agents SDK docs recommend the SDK path when application servers own
  orchestration, runtime behavior, state, and approvals:
  <https://developers.openai.com/api/docs/guides/agents>
- The Agents SDK running-agents docs define session-backed continuation as one
  conversation strategy for persistent state controlled by the application:
  <https://developers.openai.com/api/docs/guides/agents/running-agents#choose-one-conversation-strategy>
- OpenAI's external/custom endpoint docs require OpenAI-compatible chat
  completions endpoints for custom model endpoints:
  <https://developers.openai.com/api/docs/guides/external-models#custom-endpoints>

## Boundary

The harness uses one OpenAI Agents SDK `SQLiteSession` per role:

- attacker: separate SDK session id and Badlands actor prompt;
- defender: separate SDK session id and defender-only observation surface;
- green: separate SDK session id and mission-user observation surface.

SDK session state can affect the next SDK call for the same role, but it is not
environment truth. The canonical environment state is still the Badlands trace:

- `llm_decision` and `llm_decision_invalid` preserve raw model decisions,
  observations, evidence ids, and `inference_telemetry`;
- `state_transition(kind=campaign_memory_visible)` records the campaign memory
  item visible to a role in the current step and points back to the upstream
  source trace/event ids;
- `score_snapshot` is replay-derived from JSONL events;
- `badlands-replay` must reproduce the score without SDK session files.

Campaign memory is intentionally narrow. Step-2 role memory is extracted only
from that role's step-1 `llm_decision` observation and visible evidence ids.
Hidden state, scorer evidence, future schedules, privileged service truth, and
cross-role decisions are rejected before memory is injected.

DS-30 adds Badlands-owned context compaction for this campaign memory path.
The harness estimates role memory pressure against the advertised/effective
served context recorded for that role, warns near 70%, compacts near 85%, and
hard-stops near 95% if role-visible memory cannot be reduced safely. Compaction
preserves configured head and recent facts verbatim, deterministically
summarizes only older middle facts, and carries upstream source event ids on
each compacted fact. SDK session internals, cache contents, scorer truth,
hidden labels, future schedules, privileged service truth, and cross-role
decisions remain forbidden compaction inputs.

Long-term continuity comes from Badlands JSONL campaign memory, not unbounded
SDK transcript growth. Direct SDK runs use a bounded SDK session tail by default
and record `sdk_session_strategy` in the campaign report. This keeps recent
conversation mechanics available to the SDK while older continuity is carried
through trace-linked campaign memory and compaction summaries.

This is the first Badlands surface where cross-episode campaign memory exists.
It does not permit prompt self-modification, scaffold mutation, arbitrary host
tools, unsafe offensive capability, agent-authored scenario changes, or custom
compaction outside this explicit campaign-memory path.

## Commands

Deterministic adapter smoke for local tests:

```bash
uv run badlands-agents-sdk-campaign \
  --sdk-mode adapter \
  --seed 7 \
  --steps 2 \
  --until 40 \
  --out runs/ds29-adapter-smoke
```

Direct Agents SDK live campaign against the current DGX Spark tunnels:

```bash
BADLANDS_LLM_TIMEOUT_SECONDS=240 \
BADLANDS_ATTACKER_LLM_BASE_URL=http://127.0.0.1:18000/v1 \
BADLANDS_ATTACKER_LLM_API_KEY=EMPTY \
BADLANDS_ATTACKER_LLM_MODEL=NVIDIA-Nemotron-3-Super-120B-A12B-NVFP4 \
BADLANDS_DEFENDER_LLM_BASE_URL=http://127.0.0.1:18001/v1 \
BADLANDS_DEFENDER_LLM_API_KEY=EMPTY \
BADLANDS_DEFENDER_LLM_MODEL=badlands-defender-nemotron-nano \
BADLANDS_GREEN_LLM_BASE_URL=http://127.0.0.1:18002/v1 \
BADLANDS_GREEN_LLM_API_KEY=EMPTY \
BADLANDS_GREEN_LLM_MODEL=badlands-green-qwen35-2b \
uv run badlands-agents-sdk-campaign \
  --sdk-mode direct \
  --seed 7 \
  --steps 2 \
  --until 40 \
  --out runs/ds29-live-campaign
```

Replay remains JSONL-only:

```bash
uv run badlands-replay runs/ds29-live-campaign/step-2.jsonl
```

## Report Contract

The harness writes `campaign-report.json` under `--out`. Reviewer-ready fields:

- `campaign_id`, `harness_version`, `sdk_mode`, `memory_mode`;
- `compaction_mode`, compaction thresholds, compaction counts/events, and
  per-role token pressure before/after compaction;
- `sdk_session_ids` and `sdk_session_db`;
- `sdk_session_strategy` with the bounded SDK tail item limit;
- endpoint `preflight` for direct SDK mode;
- per-step trace path, replay status, score, decisions, and decision-quality
  summary;
- `role_memory` with upstream step-1 trace paths and event ids;
- `step2_memory_effects` showing role, decision event id, current-trace memory
  evidence id, action, and rationale;
- qualitative output samples for attacker, defender, and green;
- telemetry totals for tokens, attempts, repairs, invalid decisions, latency,
  and role session ids;
- canonicality marker showing SDK sessions are not required for replay.

## Qualitative Inspection

Reviewer inspection should verify:

- attacker step-2 behavior progresses from prior visible results instead of
  repeating blindly;
- defender memory is used for evidence gathering or blast-radius reasoning,
  without hidden compromise truth;
- green remains mission-user-like and does not depend on SOC/scorer truth;
- all roles cite only event ids present in their observation;
- invalid output, repairs, repeated actions, and invented evidence ids remain
  preserved as measurement signal.
