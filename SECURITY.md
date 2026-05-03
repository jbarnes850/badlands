# Security Policy

Badlands is a contained local research environment for mission-realistic cyber
self-play measurement. It is not an offensive tool suite and does not provide
arbitrary shell access, external targeting, agent-authored exploit tooling, or
unbounded network execution.

## Supported Use

Use Badlands only against local scenarios, fixtures, and services you own or are
explicitly authorized to test. The built-in attacker and defender actions are
bounded environment actions whose effects are recorded in replayable JSONL
traces.

Do not modify Badlands to target third-party systems, bypass access controls, or
deploy autonomous offensive tooling outside a contained environment.

## Reporting Vulnerabilities

Please report security issues privately before public disclosure. Include:

- affected commit or version;
- reproduction steps;
- expected and observed behavior;
- whether the issue could escape the contained environment or expose hidden
  state to an actor.

If GitHub private vulnerability reporting is enabled for this repository, use
that channel. Otherwise, contact the repository owner directly.

## Evidence Integrity Issues

Please also report issues that compromise measurement integrity, including:

- hidden labels, scorer truth, or future state reaching an actor observation;
- cross-role memory, cache, session, or telemetry leakage;
- replay divergence from JSONL traces;
- score fields without trace event evidence;
- invalid model behavior being silently repaired into success.
