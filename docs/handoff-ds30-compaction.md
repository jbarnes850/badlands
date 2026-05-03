# DS-30 Compaction Handoff

## Status

DS-30 is complete and marked Done in Linear.

Commits:

- `a9db43f` - DS-30 add evidence-preserving campaign compaction
- `a637f36` - DS-30 record compaction smoke ledger

## What Changed

- Added Badlands-owned campaign memory compaction in `badlands/agents/context_compaction.py`.
- Added token pressure thresholds: warning 70%, compaction 85%, hard stop 95%.
- Compaction preserves configured head and recent role-visible facts, summarizes older middle facts, and retains upstream source event ids.
- Added `state_transition(kind=campaign_memory_compacted)` for trace-visible compaction evidence.
- Added bounded SDK session tail strategy via `--sdk-session-item-limit` so long-term continuity comes from Badlands JSONL campaign memory rather than unbounded SDK transcript growth.
- Campaign report now records `compaction_mode`, thresholds, compaction records, per-role token pressure, served context by role, and `sdk_session_strategy`.
- `runs/run-ledger.jsonl` has an approved DS-30 smoke entry.

## Verification

Commands passed:

```bash
uv run --extra dev ruff check badlands tests
uv run --extra dev python -m pytest -q tests/test_agents_sdk_campaign.py
uv run --extra dev python -m pytest -q
uv run badlands-agents-sdk-campaign --sdk-mode adapter --seed 7 --steps 2 --until 40 --out runs/compaction-adapter-smoke
uv run badlands-replay runs/compaction-adapter-smoke/step-2.jsonl
```

Observed results:

- Targeted campaign tests: `11 passed`.
- Full test suite: `124 passed, 1 skipped`.
- Adapter smoke replay matched `runs/compaction-adapter-smoke/campaign-report.json`.
- Run-ledger schema validation passed.
- Artifact inspection confirmed distinct role session ids, replay canonicality, role memory isolation, and no forbidden hidden/scorer/cache/session/cross-role terms in actor-visible campaign memory.

## Artifacts

- `runs/compaction-adapter-smoke/campaign-report.json`
- `runs/compaction-adapter-smoke/step-1.jsonl`
- `runs/compaction-adapter-smoke/step-2.jsonl`
- `runs/compaction-adapter-smoke/cache/`
- `runs/compaction-adapter-smoke/agents-sdk-sessions.sqlite`
- `runs/run-ledger.jsonl`

## Residual Risk

The 2-step adapter smoke does not naturally exceed the compaction threshold. Over-threshold behavior is covered by targeted tests, but a longer rehearsal should confirm live pressure behavior before the final 6-hour run.

## Recommended Next Gate

Before the final 6-hour run:

1. Serve attacker, defender, and green/user at the intended context target.
2. Run a 10-20 minute live rehearsal with campaign memory enabled.
3. Verify per-role token pressure, bounded SDK session strategy, trace replay, score evidence, and compaction metadata.
4. Proceed to the 6-hour run only if endpoint preflight, replay, and artifact inspection pass.
