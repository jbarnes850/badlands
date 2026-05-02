# DGX Spark live inference

Live Spark inference is an opt-in verification path for LLM-backed actors. Normal Badlands tests must remain deterministic/offline through cached LLM decisions.

## Current serving state

| Role | Endpoint | Served model id | Host | Port | Context | Notes |
|---|---|---|---|---:|---:|---|
| Attacker | primary Spark | `NVIDIA-Nemotron-3-Super-120B-A12B-NVFP4` | `spark-f7e2` | 8000 | 32768 | primary high-capability attacker model |
| Defender | secondary Spark | `badlands-defender-nemotron-nano` | `spark-cfd0` | 30000 | 32768 | NVIDIA Nemotron 3 Nano 30B A3B NVFP4, explicit 16G KV, logged KV capacity 1,118,464 tokens |
| Green user sim | secondary Spark | `badlands-green-qwen35-2b` | `spark-cfd0` | 30001 | 32768 | Qwen3.5-2B, explicit 12G KV, logged KV capacity 524,208 tokens |

All three endpoints have responded to `/v1/models` and completed JSON chat requests.

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

Safety: LLM actors propose structured actions only. The environment validates actions and restricts attacker actions to the local Badlands enclave. No arbitrary shell execution or external targeting is permitted.
