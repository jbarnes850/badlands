# DGX Spark live inference

Live Spark inference is an opt-in verification path for LLM-backed actors. Normal Badlands tests must remain deterministic/offline through cached LLM decisions.

## Current serving state

| Role | Endpoint | Served model id | Host | Port | Context | Notes |
|---|---|---|---|---:|---:|---|
| Attacker | primary Spark | `NVIDIA-Nemotron-3-Super-120B-A12B-NVFP4` | `spark-f7e2` | 8000 | 32768 | primary high-capability attacker model |
| Defender | secondary Spark | `badlands-defender-nemotron-nano` | `spark-cfd0` | 30000 | 32768 | NVIDIA Nemotron 3 Nano 30B A3B NVFP4, explicit 16G KV, logged KV capacity 1,118,464 tokens |
| Green user sim default | secondary Spark | `badlands-defender-nemotron-nano` | `spark-cfd0` | 30000 | 32768 | shares endpoint infrastructure with defender, but uses separate Badlands actor, role prompt, observation surface, cache key, and trace events |
| Green rollback/specialized | secondary Spark | `badlands-green-qwen35-2b` | `spark-cfd0` | 30001 | 32768 | Qwen3.5-2B, explicit 12G KV, rollback/specialized-green only unless measured behavior wins |

All three endpoints have responded to `/v1/models` and completed JSON chat requests.

The 32768-token context shown above is a smoke/liveness serving profile. It is
not sufficient evidence for DS-29 campaign continuity or long-horizon
capability-curve claims. Before DS-29 or later 1-hour/3-hour/6-hour runs are
treated as representative, increase and record the effective served context by
role. Prefer the largest stable vLLM context the endpoint can serve without KV
preemption, saturation, or unacceptable latency. Record both advertised model
context and effective served context in the live report and run ledger.

## Primary Spark access

- SSH alias: `spark`
- Hostname: `spark-f7e2`
- Tailscale IP: `100.70.91.108`
- OpenAI-compatible endpoint on remote host: `http://localhost:8000/v1`

Start all canonical tunnels with:

```bash
scripts/start-live-llm-tunnels.sh
```

Manual attacker tunnel:

```bash
ssh -N -L 18000:localhost:8000 spark
```

## Secondary Spark access

- Host: `spark-cfd0`
- Tailscale IP: `100.113.207.120` when reachable
- LAN IP from primary: `192.168.100.11`
- User: `jarrodbarnes`

Use jump host access:

```bash
ssh -J spark jarrodbarnes@192.168.100.11
```

Manual defender and green tunnels through the primary:

```bash
ssh -J spark -N -L 18001:localhost:30000 jarrodbarnes@192.168.100.11
ssh -J spark -N -L 18002:localhost:30001 jarrodbarnes@192.168.100.11
```

## Recommended Badlands env vars

```bash
export BADLANDS_LIVE_LLM=1

export BADLANDS_ATTACKER_LLM_BASE_URL="http://localhost:18000/v1"
export BADLANDS_ATTACKER_LLM_API_KEY="EMPTY"
export BADLANDS_ATTACKER_LLM_MODEL="NVIDIA-Nemotron-3-Super-120B-A12B-NVFP4"

export BADLANDS_DEFENDER_LLM_BASE_URL="http://localhost:18001/v1"
export BADLANDS_DEFENDER_LLM_API_KEY="EMPTY"
export BADLANDS_DEFENDER_LLM_MODEL="badlands-defender-nemotron-nano"

export BADLANDS_GREEN_LLM_BASE_URL="http://localhost:18002/v1"
export BADLANDS_GREEN_LLM_API_KEY="EMPTY"
export BADLANDS_GREEN_LLM_MODEL="badlands-green-qwen35-2b"
```

Default shared-Nano validation uses the defender Nano for green:

```bash
export BADLANDS_GREEN_LLM_BASE_URL="http://localhost:18001/v1"
export BADLANDS_GREEN_LLM_API_KEY="EMPTY"
export BADLANDS_GREEN_LLM_MODEL="badlands-defender-nemotron-nano"
```

Backwards-compatible global vars still work for single-endpoint smoke tests:

```bash
export BADLANDS_LLM_BASE_URL="http://localhost:18000/v1"
export BADLANDS_LLM_API_KEY="EMPTY"
export BADLANDS_LLM_MODEL="NVIDIA-Nemotron-3-Super-120B-A12B-NVFP4"
```

## Verification commands

```bash
scripts/start-live-llm-tunnels.sh
BADLANDS_LIVE_LLM=1 uv run --extra dev python -m pytest -q tests/test_live_llm_spark.py
uv run badlands-episode \
  --green-actor llm \
  --attacker-actor llm \
  --defender-actor llm \
  --trace runs/live-three-endpoint-smoke.jsonl
```

## DS-24 live validation harness

One command runs endpoint preflight, a bounded role-isolated live episode,
trace replay, and a compact JSON report:

```bash
BADLANDS_LIVE_LLM=1 \
BADLANDS_LLM_TIMEOUT_SECONDS=240 \
BADLANDS_ATTACKER_LLM_BASE_URL=http://127.0.0.1:18000/v1 \
BADLANDS_ATTACKER_LLM_API_KEY=EMPTY \
BADLANDS_ATTACKER_LLM_MODEL=NVIDIA-Nemotron-3-Super-120B-A12B-NVFP4 \
BADLANDS_DEFENDER_LLM_BASE_URL=http://127.0.0.1:18001/v1 \
BADLANDS_DEFENDER_LLM_API_KEY=EMPTY \
BADLANDS_DEFENDER_LLM_MODEL=badlands-defender-nemotron-nano \
BADLANDS_GREEN_LLM_BASE_URL=http://127.0.0.1:18001/v1 \
BADLANDS_GREEN_LLM_API_KEY=EMPTY \
BADLANDS_GREEN_LLM_MODEL=badlands-defender-nemotron-nano \
uv run badlands-live-validate \
  --seed 7 \
  --until 40 \
  --trace runs/live-validation-shared-nano.jsonl \
  --cache /tmp/badlands-live-validation-shared-nano-cache \
  --report runs/live-validation-shared-nano-report.json
```

The harness checks `/v1/models`, configured model IDs, bounded JSON chat
compatibility, endpoint availability, TTFT availability, and vLLM `/metrics`
backpressure evidence when exposed by the local server. If TTFT or Prometheus
metrics are unavailable, the report records explicit unavailable markers rather
than silently treating serving bottlenecks as disproven. A completed run must
contain `score_snapshot`; otherwise the command exits nonzero and writes the
exact blocker to the report path.

The report separates endpoint failure, serving bottleneck, agent-loop
bottleneck, and environment failure. It includes wall-clock time, output
tokens/sec, per-role latency, invalid-decision rate, repair count, replay
result, score summary, trace path, cache path, role-isolation metadata, and
qualitative samples of attacker/defender/green outputs.

Repair accounting is attempt-based. `repair_count`/`repairs_attempted` means a
repair call was actually made; final malformed repaired output increments
`repair_invalid_count`, `final_invalid_count`, and `parse_failures`, but does
not increment `repair_count` a second time.

Invalid LLM decisions are qualitative artifacts, not just counters. The trace
and report preserve malformed raw outputs after repair exhaustion so reviewers
can distinguish truncation, prompt/interface mismatch, evidence-ID drift,
schema brittleness, and endpoint failures.

The command also prints live operator logs to the terminal for preflight checks,
due role batches, valid/invalid LLM decisions, action application, replay, and
report creation. Use `--quiet` only when another process is tailing the JSONL
trace/report directly.

The live harness snapshots independent role observations before fan-out, runs
LLM proposal calls concurrently, and applies actions after deterministic fan-in
using role order `green`, `attacker`, `defender`. Badlands JSONL remains the
canonical replay source; endpoint state, cache state, and future SDK session
state are not required for replay.

If the f7 Super attacker endpoint is saturated, cfd0 Nano may be used as an
attacker fallback only for liveness validation. Mark the report as
liveness-only by preserving the endpoint/model fields; do not compare it to
Super capability behavior.

## DS-29 handoff boundary

DS-24 exposes only live inference telemetry, role-isolation guarantees,
deterministic fan-in semantics, and passive correlation fields. DS-29 owns
durable actor memory, campaign compaction, multi-episode state persistence,
and OpenAI Agents SDK sessions.

The Agents SDK campaign harness should consume these DS-24 fields:

- `role`, `endpoint`, `model`, `cache_key`, `cache_hit`
- `prompt_token_estimate`, `completion_tokens`, `wall_latency_s`
- `attempt_count`, `repair_count`, `validation_error`, `invalid_decision_reason`
- `badlands_event_id`, `trace_path`, optional `sdk_run_id`, optional `sdk_session_id`
- advertised and effective served context by role when available

Per the OpenAI Agents SDK docs, SDK use is appropriate when the application
owns orchestration, tool execution, approvals, and state. DS-29 should keep
separate role sessions for attacker, defender, and green, choose explicit
models per role, and treat SDK run/session IDs as observability metadata rather
than canonical environment truth.

For the current Badlands definition, co-evolution means within-run adaptation
through role memory and across-episode adaptation through campaign state. It
does not include prompt/scaffold self-modification, arbitrary tool invention,
or agent-authored scenario changes.

Safety: LLM actors propose structured actions only. The environment validates actions and restricts attacker actions to the local Badlands enclave. No arbitrary shell execution or external targeting is permitted.
