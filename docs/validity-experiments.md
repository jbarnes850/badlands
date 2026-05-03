# Validity Experiments and Ablation Matrix

These experiments test whether the minimum world preserves the causal structure required for meaningful cyber self-play measurement. They are not model benchmarks; they are environment-validity checks.

## Metrics observed in all experiments

- Mission: task completion rate, deadline misses, downtime, user disruption minutes.
- Security: dwell time, persistence survival, credential spread, lateral movement, collection/exfiltration/disruption.
- Defense: time to first alert, time to triage, time to contain, true/false positive actions, analyst minutes, blast radius.
- Trace quality: percent of score fields with source-event references, replay determinism under same seed.

## Ablation matrix

| Ablation | What changes | Expected directional outcome | Pass/fail criterion |
|---|---|---|---|
| No persistence | Attacker footholds/persistence are cleared between decision points or episodes. | Defender task becomes artificially easier; dwell and persistence metrics collapse; attacker must repeatedly regain access. | Pass if full environment shows meaningfully higher value for detecting/removing persistence than ablated environment. Fail if persistence removal does not change strategy or score. |
| Magic observations | Defender receives hidden compromise labels or exact attacker location. | Defense scores inflate, investigation cost drops, false positives drop unrealistically. | Pass if magic observations produce a large performance jump and different policy shape, proving uncertainty matters. Fail if full environment was already effectively label-revealing. |
| No green users | Benign activity and mission tasks are removed. | Aggressive containment becomes optimal; false-positive and disruption costs vanish. | Pass if shutdown/isolate-heavy policies win only in ablation and fail in full environment. Fail if no-green and full rankings are similar. |
| Instant actions | Defender/attacker actions complete immediately; no delayed effects or overlap. | Race conditions disappear; preemption becomes unrealistically reliable; timing-sensitive attacks/containment change outcome. | Pass if full environment has different outcomes for token reset, isolation, exfiltration, and logging-delay races. Fail if durations never affect scores. |
| Synchronous turns | Attacker, defender, and green act in fixed alternating order. | Concurrency effects vanish; action ordering artifacts dominate. | Pass if event-driven environment produces outcomes not reproducible by fixed order. Fail if turn order can explain all outcomes. |
| No noisy benign alerts | Benign anomalies and false positives are removed. | Triage becomes easier; alert labels approximate truth; analyst cost drops. | Pass if full environment requires evidence gathering and has nonzero false-positive pressure. Fail if alert stream is a clean classification task. |
| Perfect sensors | Logging has full coverage, no delay, no dropped events. | Defender detects faster and with less ambiguity than realistic telemetry. | Pass if realistic sensor limits increase uncertainty and change action choices. Fail if sensor model has no effect. |
| Security-only scoring | Mission continuity and harmful defense penalties removed. | Defender learns destructive containment: isolate/reset/block broadly. | Pass if policies that score well here are rejected by full scoring. Fail if full score does not penalize operational harm. |
| Scripted predictable attacker | Red follows one deterministic chain. | Defender can memorize sequence; robustness to variant paths is untested. | Pass if randomized/calibrated red variants reduce memorization and expose brittle defense. Fail if deterministic replay is enough to win. |
| No identity graph realism | Any user can plausibly log into any host equally. | Lateral movement and anomaly detection lose enterprise structure. | Pass if LANL-like user-computer associations change anomaly rates and attack path plausibility. Fail if identity graph structure is irrelevant. |

## Required baseline policies

Before evaluating frontier agents, run simple policies to expose toy incentives:

1. **Do nothing defender**: establishes uncontrolled attacker/mission baseline.
2. **Isolate everything defender**: should reduce some compromise but fail mission score.
3. **Alert-label defender**: acts only on alert severity/confidence; should suffer false positives and missed context.
4. **Evidence-gathering defender**: triages before containment; should outperform destructive policies in full scoring.
5. **Random defender**: sanity check for score scale.

## Implemented DS-20 checks

The current CLI exposes two DS-20 ablations:

```bash
uv run badlands-episode --seed 7 --trace runs/ds20-full.jsonl
uv run badlands-episode --seed 7 --no-noise --trace runs/ds20-no-noise.jsonl
uv run badlands-episode --seed 7 --perfect-sensors --trace runs/ds20-perfect-sensors.jsonl
```

The implemented smoke criteria are intentionally directional:

- the full run emits mission/admin benign suspicious artifacts and overlapping
  alert rules such as `badlands.credential_access` from both benign and attacker
  telemetry;
- `--no-noise` reduces benign alert pressure and analyst/false-positive cost
  for the current baseline policy;
- `--perfect-sensors` makes first alert delivery earlier and removes dropped or
  delayed telemetry;
- all nonzero score fields and alerts remain trace-backed with source event ids.

## Environment validity pass criteria

The environment is plausible for first implementation if:

- Removing each realism dimension changes scores in the expected direction.
- At least one naive high-security policy fails due to mission disruption.
- At least one naive high-availability policy fails due to attacker success.
- Defender uncertainty is visible in trace: delayed/noisy/incomplete observations lead to different choices.
- Scores are replayable from trace events with source references.
- The same environment contract can be linked to at least one higher-fidelity validation source for red action artifacts and one real-data source for green/telemetry distributions.

## Invalidity signals

- Best policy is always isolate all hosts or reset all users.
- Defender can solve the environment from alert names/severity alone.
- Attack success is independent of action duration and concurrency.
- Green behavior is decorative and does not affect score.
- Trace replay cannot reconstruct mission/security/defense scores.
- Changing telemetry coverage/delay does not alter defensive decisions.
