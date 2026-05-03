# Realism Provenance Crosswalk

This is the reviewer-facing evidence ledger for Badlands environment realism.
It separates implemented evidence from assumptions and planned calibration so
validity claims do not drift beyond the artifacts in the repo.

Status values:

- `implemented`: behavior exists in code, trace, tests, or service contracts.
- `partial`: the mechanism exists, but calibration or coverage is incomplete.
- `planned`: explicit validation path exists; behavior is not implemented yet.
- `assumption`: scenario or scoring choice that still needs mission-owner or
  higher-fidelity validation.

## Source Index

| Source | Anchor Used |
|---|---|
| NCSC frontier-AI defender guidance: <https://www.ncsc.gov.uk/blogs/why-cyber-defenders-need-to-be-ready-for-frontier-ai> | Continuous cyber measurement, defender advantage, telemetry quality, mission continuity, and harmful-response risk. |
| Building Better Environments for Autonomous Cyber Defence: <https://arxiv.org/pdf/2604.08805v1> | Virtualisation gap and modelling-gap taxonomy: network/host, user/threat, sequence, observation, action, and reward modelling. |
| DARPA OpTC: <https://github.com/FiveDirections/OpTC-data> | Endpoint telemetry shape and adversarial-plus-benign event style. |
| LANL cyber datasets: <https://csr.lanl.gov/data/cyber1/> and <https://csr.lanl.gov/data/> | Long-duration enterprise auth/event rhythms and user-host affinity structure. |
| Mordor / OTRF Security Datasets: <https://mordordatasets.com/> and <https://github.com/OTRF/mordor> | ATT&CK-mapped adversarial telemetry and replayable detection examples. |
| MITRE CALDERA: <https://caldera.mitre.org/> and <https://github.com/mitre/caldera> | Adversary emulation abilities, operational plugins, prerequisites, durations, and artifacts for later calibration. |
| MITRE ATT&CK: <https://attack.mitre.org/> | Shared tactic/technique labels for attacker actions and detections. |
| Elastic Common Schema: <https://www.elastic.co/guide/en/ecs/current/index.html> | Defender-facing normalized endpoint, auth, file, network, and service fields. |
| Elastic detection-rules: <https://github.com/elastic/detection-rules> | Rule metadata, severity, risk, ATT&CK tags, and false-positive notes. |
| Sigma: <https://sigmahq.io/> and <https://github.com/SigmaHQ/sigma> | Vendor-agnostic detection rule structure and detection-engineering workflow. |
| NIST SP 800-61 Rev. 2: <https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final> | Incident response phases and defender workflow framing. |
| CISA incident and vulnerability response playbooks: <https://www.cisa.gov/news-events/news/incident-and-vulnerability-response-playbooks> | Operational response, communication, and recovery workflow grounding. |
| Cyberwheel: <https://github.com/ORNL/cyberwheel> | Active cyber-defense simulator/emulator direction and realistic monitoring aspiration. |
| CybORG: <https://github.com/cage-challenge/CybORG> | Established ACD benchmark reference point and comparison surface. |
| NASimEmu: <https://github.com/jaromiru/NASimEmu> | Sim-to-emulation validation path for abstract network attack actions. |

## Mechanism Crosswalk

| Mechanism | Status | Realism Claim | Source Anchor | Local Artifact | Validation Plan / Unsupported Assumption |
|---|---|---|---|---|---|
| Scenario/world fixture | implemented | The measured world is an inspectable mission enclave with hosts, users, services, dependencies, workflows, attacker starting assumptions, benign noise, sensors, and field provenance. | arXiv virtualisation/modelling gap taxonomy; NCSC baseline-security and mission-continuity guidance. | `badlands/scenarios/mission_desk.json`; `docs/scenario-fixtures.md`; `tests/test_scenarios.py`. | Mission-owner review is still needed for criticality, topology size, and workflow realism. |
| Identity service | implemented | Login, session validation, account reset, lockout, unlock, file access, and attacker credential-use outcomes are backed by active local service state and trace-ingested auth telemetry. | LANL auth associations; NIST/CISA account containment workflows; NCSC access-control and harmful-response guidance. | `badlands/network/mission_app.py`; `docs/identity-service-contract.md`; `tests/test_service_integration.py`; `tests/test_defender_workflow.py`. | IdP and mission app are still co-located in one local service process; separate service deployment remains planned. |
| Mission services and workflows | implemented | Mission task completion, file reads, tickets, degraded dependency behavior, deadline misses, and ticket backlog are service-authoritative and replay-scored from trace evidence. | NCSC mission-continuity guidance; arXiv action/reward modelling; NIST/CISA ticketed response workflow; ECS service/auth fields. | `docs/mission-service-contract.md`; `badlands/network/mission_app.py`; `tests/test_service_integration.py`; `tests/test_vertical_slice.py`. | Task mix and degraded-mode probabilities are heuristic until DS-26 calibration. |
| Green behavior and benign noise | partial | Green users perform mission workflow tasks and benign-but-suspicious auth/process/file/service/ticket activity, so defense must preserve operations under uncertainty. | arXiv user simulation; LANL event rhythms; OpTC endpoint telemetry shape; NCSC warning that harmful automation can disrupt operations. | `badlands/scenarios/mission_desk.json`; `docs/scenario-fixtures.md`; `badlands/core/env.py`; `tests/test_scenarios.py`; `tests/test_validity_experiments.py`. | Rates, timing, and role/task distribution are small-fixture heuristics, not statistical LANL/OpTC reproductions. |
| Attacker actions and objectives | partial | Attacker actions are bounded Badlands actions with prerequisites, durations, trace artifacts, and mission-relevant objectives for collection, exfiltration, and disruption. | ATT&CK tactic labels; Mordor/OTRF adversarial telemetry examples; CALDERA emulation abilities; NASimEmu sim-to-emulation direction. | `badlands/core/env.py`; `badlands/core/attacker_actions.py`; `docs/trace-schema.md`; `tests/test_attacker_objectives.py`. | Durations/artifacts are ATT&CK-shaped but not yet calibrated against CALDERA/Mordor/OpTC replay traces. |
| Defender actions and case workflow | implemented | Defender actions map to evidence gathering, identity/endpoint/network queries, containment, reset, rollback, escalation, analyst time, blast radius, and delayed action results. | NIST SP 800-61; CISA playbook; NCSC harmful-response warning; arXiv action modelling. | `badlands/core/defender_actions.py`; `badlands/core/env.py`; `docs/environment-contract.md`; `tests/test_defender_workflow.py`. | Action duration constants and failure probabilities still need workflow/emulation calibration. |
| Observation surfaces and sensors | implemented | Actors receive role-valid observations only: logs, alerts, tickets, EDR-like slices, mission user outcomes, or attacker command results; sensor coverage/drop/delay creates partial evidence. | arXiv observation modelling; ECS; Elastic detection-rules; Sigma; OpTC/LANL telemetry patterns. | `badlands/core/observations.py`; `docs/trace-schema.md`; `tests/test_vertical_slice.py`; `tests/test_scenarios.py`; `tests/test_live_validate.py`. | Full EDR/SIEM volume and schema coverage are reduced; no claim of production log-rate fidelity. |
| Timing and concurrency | implemented | The environment uses an event-driven clock with action durations, delayed telemetry/alerts, overlapping green/attacker/defender effects, and replayable race outcomes. | arXiv sequence modelling and continuous-vs-discrete cyber activity framing. | `badlands/core/env.py`; `docs/environment-contract.md`; `tests/test_vertical_slice.py`; `tests/test_dependency_graph.py`. | Instant-action and synchronous-turn ablations remain planned inventory items, not implemented checks. |
| Scoring and replay evidence | implemented | Mission, security, and defense-quality scores are recomputed from JSONL trace events with source evidence, not hidden labels or SDK/session state. | arXiv reward modelling and evaluation beyond episodic reward; NCSC mission-harm framing. | `badlands/scoring/replay.py`; `docs/trace-schema.md`; `tests/test_vertical_slice.py`; `tests/test_attacker_objectives.py`; `tests/test_agents_sdk_campaign.py`. | Score weights are first-slice review values, not mission-owner calibrated utility weights. |
| Validity ablations | partial | The validity runner checks whether removing realism dimensions changes risk and policy behavior directionally. Supported ablations fail/replay/leak-check explicitly; unsupported advertised ablations fail loudly unless allowed. | arXiv evaluation beyond average reward; NCSC continuous measurement motivation. | `badlands/validity_experiments.py`; `docs/validity-experiments.md`; `tests/test_validity_experiments.py`; `runs/ds23-validity/`. | Current supported set covers persistence, magic observations, no green users, no benign noise, and perfect sensors; instant actions, synchronous turns, security-only scoring, scripted attacker, and identity-graph ablations remain planned. |
| Live inference and model-output review | implemented | Live LLM validation records endpoint preflight, role isolation, raw/valid/invalid decisions, repairs, token/latency telemetry, replay, qualitative outputs, and decision-quality rubric summaries. | NCSC cost/speed/capability motivation; OpenAI-compatible endpoint requirements; arXiv observation/action/reward audit concerns. | `badlands/live_validate.py`; `docs/dgx-spark-live-inference.md`; `docs/model-output-rubric.md`; `tests/test_live_validate.py`; `tests/test_decision_quality.py`; `runs/run-ledger.jsonl`. | Current 32768-token served context is smoke/liveness evidence, not representative long-horizon capability evidence. |
| Campaign/session memory | implemented | DS-29 adds role-isolated OpenAI Agents SDK sessions and trace-visible campaign memory while keeping Badlands JSONL canonical for replay/scoring. | OpenAI Agents SDK session strategy docs; arXiv sequence/observation modelling; NCSC continuous measurement motivation. | `badlands/campaigns/agents_sdk_smoke.py`; `badlands/agents/campaign_memory.py`; `docs/agents-sdk-campaign.md`; `tests/test_agents_sdk_campaign.py`; `runs/ds29-live-campaign/`. | Two-step smoke only; memory summarizes prior role-visible decisions, not full long-horizon campaign state. |
| Sim-to-emulation calibration hooks | partial | Selected scan, credential access, lateral movement, collection, isolate, reset, and restore actions emit read-only calibration metadata with source anchors, preconditions, expected artifacts, duration ranges, confidence, and explicit warnings. | CALDERA, NASimEmu, Cyberwheel, Mordor/OpTC, LANL, NIST/CISA, NCSC, ATT&CK. | `badlands/calibration/action_calibration.json`; `badlands/core/calibration.py`; `docs/calibration-hooks.md`; `tests/test_calibration.py`. | Initial records are `heuristic` and low-confidence; no record is `calibrated` until a reviewed replay/emulation artifact is attached. |

## Unsupported Assumption Ledger

These are allowed only as explicit assumptions until DS-26 or later work closes
them:

- Action durations, degraded-mode probabilities, and sensor drop/delay values
  are heuristic smoke values. DS-26 records expose this status; they do not
  convert constants into measured calibration.
- The default mission enclave is compact and local; it is not a production
  enterprise topology.
- Green workflow rates and roles are scenario-authored, not statistically
  fitted to a mission-owner calendar.
- Current attacker action artifacts are ATT&CK-shaped and trace-backed, but not
  calibrated to CALDERA/Mordor/OpTC execution traces.
- Current live/campaign runs are smoke evidence. They are not long-horizon
  capability-curve evidence until served context, wall-clock budget, campaign
  state, and cost/power class are measured by role.

## Reviewer Use

Before approving a realism claim, check:

- the mechanism appears in the crosswalk;
- the status is not overstated;
- at least one source anchor is cited;
- at least one local artifact, test, trace, or validation plan is named;
- the claim does not imply calibration when the row lists a heuristic or
  planned validation path.
