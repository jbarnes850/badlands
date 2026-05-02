# Identity Service Contract

Badlands identity is now an active local HTTP service, co-located with the mission service for the first environment-validity slice. Python may schedule actions and cache observed results, but identity truth for login, session validation, account reset, lockout, and credential use is owned by the service.

## Endpoints

- `POST /idp/login`: accepts `user`, `host`, and `password`; returns an IdP session when the account exists, is not locked, and the password matches.
- `POST /idp/validate`: accepts `user`, `host`, `session_id`, and `service`; succeeds only for an active IdP session on an unlocked account.
- `POST /idp/reset`: defender containment action; locks the user and revokes all sessions.
- `POST /idp/use_credential`: attacker credential-use validation; succeeds only when the credential matches an unlocked IdP account.
- `POST /idp/unlock`: rollback support for reset-induced lockout.
- `GET /file/<name>`: mission app access; requires a valid IdP session in `X-Session`.
- `GET /logs?run_id=<run>`: returns service-emitted telemetry for the current run.

## Auth Telemetry

Every IdP action emits an ECS-like authentication record with:

- `@timestamp`
- `run_id`
- `event.category=authentication`
- `event.dataset=badlands.idp`
- `event.action`
- `event.outcome`
- `event.reason`
- `user.name`
- `source.host`
- `destination.service`
- optional `session.id`

The environment ingests these service logs as `telemetry_emitted` events with `category=auth`. Mission failures from lockout or invalid sessions include `source_event_ids` pointing at the IdP/auth telemetry, and scoring continues to replay from trace evidence rather than hidden identity labels.

## Realism Anchor

This slice closes a high-leverage virtualization gap identified by arXiv 2604.08805: auth outcomes are grounded in active service state instead of simulator-only labels. LANL auth associations still shape green user-host selection. NCSC frontier-AI defender guidance motivates high-quality telemetry and harmful-defense penalties for disruptive resets. NIST/CISA incident-response workflows anchor account reset and revocation as realistic containment actions with operational blast radius.
