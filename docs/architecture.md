# Badlands Architecture

Badlands has four first-class components. The active network environment is the world; the agents are processes that act inside it.

## 1. Attacker agent

The attacker agent controls an intrusion attempt against the mission enclave. It receives only attacker-visible observations: command output, service banners, accessible files, discovered credentials, error messages, and delayed results from tools it actually ran. It does not see defender state, hidden compromise labels, green schedules, or scoring fields.

Initial proof workflow: a phished mission analyst workstation or stolen user credential gives the attacker a foothold. The attacker attempts discovery, credential access, persistence, lateral movement to the file share or mission app tier, collection, exfiltration, or mission disruption.

## 2. Defender agent

The defender agent represents a SOC/mission-defense analyst or autonomous defense system. It receives only defender-facing artifacts: SIEM alerts, ECS-like normalized events, EDR process/file/network telemetry, identity/auth logs, DNS/network summaries, user tickets, asset inventory, case notes, and delayed results from defensive actions.

It must triage uncertain evidence, choose investigations, contain or monitor, reset credentials, block indicators, isolate hosts, restore services, escalate, and roll back harmful actions. It never receives simulator truth such as `host_compromised=true`.

## 3. User simulator / green agent

The green agent simulates benign mission users and routine administrative activity. It creates the mission value being protected and the background noise that makes defense non-trivial. It logs in, opens files, uses the mission app, sends email, creates tickets, runs scheduled scripts, and occasionally triggers benign anomalies.

Green activity must affect scoring: a defender that protects the network by locking users out, isolating critical hosts, or blocking mission dependencies fails.

## 4. Active network environment

The active network is not a passive data object. It is the stateful world containing:

- hosts, roles, processes, services, files, network segments, and mission dependencies;
- identities, groups, sessions, credentials, MFA/reset state, and privileges;
- attacker footholds, persistence, discovered credentials, and in-flight operations;
- green task queues, deadlines, app/file availability, and user productivity;
- telemetry buffers, logging delay, sensor coverage, dropped/noisy events, alerts, and tickets;
- action durations, delayed effects, concurrent execution, cooldowns, and rollback state;
- trace events and scoring evidence.

Attacker, defender, and green agents all submit actions into this environment. The environment advances time, applies preconditions and delayed effects, emits observations, writes trace events, and derives auditable scores from the trace.

## Protected mission workflow

The first workflow is a two-hour mission desk operation. Analysts must authenticate, retrieve and update mission files, use a mission web application, exchange email, and resolve operational tickets before deadlines. The file share and mission app are critical dependencies. Identity and endpoint health are enabling dependencies. The protected mission is not “keep every host uncompromised at any cost”; it is “continue mission work while detecting and containing intrusion with minimal operational harm.”

## Interfaces at a glance

| Component | Inputs | Outputs | Must not access |
|---|---|---|---|
| Attacker | Attacker observations, action budget | Attack actions | Hidden state, defender queue, scoring labels |
| Defender | Alerts, logs, telemetry, tickets, inventory, action results | Investigation and response actions | Compromise truth, attacker plan, hidden state |
| Green | Schedule, mission tasks, app/user state | Benign user actions and tickets | Attack truth, defender internals |
| Active network | All actions, clock, state | Observations, trace events, scores | N/A: owns hidden state |

## Review invariant

Implementation is valid only if every agent-facing field can be traced to a realistic artifact and every score can be recomputed from recorded trace evidence without exposing hidden simulator state to agents.
