# PCSIRM Testing Guide

## Why test database isolation matters

PCSIRM's development database contains real local development records, including
users, security events, incident history, timelines, and audit entries. Tests
must not use that database: even a test that restores an incident status can
leave timeline or audit records behind.

The test suite creates temporary SQLite databases and never passes the
development database path to test services. The development database guard
opens `instance/pcsirm.db` read-only and compares its file timestamp and
protected table contents before and after the test session.

## Pytest fixtures

- `app` creates a fresh Flask app for each test, sets `TESTING=True`, uses a
  test-only secret, initializes a unique temporary database, and removes its
  temporary directory after the test.
- `client` provides that app's Flask test client.
- `database` provides a direct connection to that test's database.
- `test_user` creates a temporary administrator with the existing password
  hashing service.
- `analyst` creates a temporary analyst.
- `authenticated_client` puts the test administrator in the Flask session.
- `test_event` creates an event using the event service.
- `development_database_guard` records and compares the development DB
  timestamp and rows in users, security events, incidents, incident timeline,
  and system audit logs.

The fixtures keep an application context active while tests call the existing
services. `get_db_connection()` uses the app's configured `DATABASE_PATH`
inside that context. Outside an app context, it retains the normal development
database fallback for command-line and normal application use.

The module-level WSGI app delays schema initialization until its first request.
The pytest session fixture redirects that app to a session-only temporary DB
before initializing it. Factory-created test apps use their own per-test
temporary databases.

## Run tests

From the project directory:

```powershell
python -m pytest -q
python -m compileall app.py backend database tests
```

`pytest` is already included in `requirements.txt`; no additional test
dependencies are required.

## Development versus test databases

Normal application configuration uses:

```text
instance/pcsirm.db
```

Each pytest app instead uses a database under a unique operating-system
temporary directory (for example, `%TEMP%\pcsirm-test-...\pcsirm-test.db`).
The directory is removed when its test fixture finishes. The test suite also
checks that the SQLite path differs from the development path and that the
test-only user, event, incident, and timeline rows are absent from the
development DB.

The module-level app used by WSGI follows the normal development configuration
when run outside pytest. During pytest, the session fixture assigns it a
separate temporary SQLite path.

## Browser session security

State-changing browser and session-authenticated endpoints require a CSRF
token. The token is created on safe requests, included in browser forms, and
may be sent by API clients in the `X-CSRFToken` header. Login rotates the
token, and logout clears the session. Tests cover missing and invalid tokens
for authentication, incident status, and monitoring-source operations.

Session cookies are secure by default. For an isolated HTTP localhost demo only,
set `PCSIRM_SESSION_COOKIE_SECURE=false`; do not use that override on a shared
network or production deployment. Set `PCSIRM_SESSION_COOKIE_SECURE=true` when
serving PCSIRM behind HTTPS. The application starts with Flask debug mode
disabled.

## Verify development records remain unchanged

The autouse `development_database_guard` takes a read-only snapshot at pytest
session start. It checks that:

- The development DB file still exists (if it existed at test start).
- Its modification timestamp is unchanged.
- Rows in users, security events, incidents, incident timeline, and system
  audit logs are unchanged, along with monitoring sources, detection rules,
  rule executions, detection alerts, simulation runs, evidence, and incident
  actions (when those tables exist in the development database).

An explicit isolation test also checks the configured paths and verifies that
test-created user, event, incident, and timeline records do not appear in the
development database. Any guard failure means tests must not be considered
isolated; inspect the failing test for a service call made outside the Flask
test app context.

For manual inspection, use SQLite read-only mode. Do not initialize, reset, or
write to `instance/pcsirm.db` as part of testing.

## Monitoring Sources testing and migration checks

The monitoring-sources module introduces a separate set of checks that must remain
isolated from the real PropertyChain environment. The default sources remain in a
planned or simulated state and are never connected automatically:

- `PropertyChain Firebase` — `FIREBASE / PLANNED / NOT_CONNECTED`
- `Ethereum Sepolia Smart Contracts` — `BLOCKCHAIN / PLANNED / NOT_CONNECTED`
- `PCSIRM Application` — `APPLICATION / SIMULATED / NOT_CONNECTED`
- `PCSIRM Simulation Engine` — `SIMULATION / SIMULATED / NOT_CONNECTED`

The monitoring source tests verify that:

- registration rejects invalid names, invalid types, invalid modes, invalid
  statuses and duplicate normalized names;
- planners and simulated sources cannot be marked connected by manual status
  changes or manual success checks;
- analysts cannot change administrative monitoring settings;
- a failed check preserves the earlier successful verification timestamp;
- audit records redact secrets, tokens, and credential-like values;
- the initialization routine is idempotent and preserves existing settings;
- the database migration adds missing columns safely and keeps existing users,
  events, incidents, timelines, and audit data intact.

There is no live Firebase or Ethereum connection active unless a separate,
verified integration is configured and tested outside the default monitoring
setup.

The simulation page runs the controlled local scenarios described below.
Reports and account settings have browser routes and isolated test coverage.

## Detection rules

Database initialization seeds a small, idempotent set of configurable
detection rules. Rules match an event type (or `*` for events from any type)
and count activity from the same source inside the configured time window.
Thresholds and windows can be changed by administrators. Event ingestion
evaluates enabled rules in the same SQLite transaction as the event write,
records execution history, creates event-linked alerts, and suppresses a
second open alert for the same rule and source during that window.

Failed PCSIRM logins are written as generic authentication events without
recording the supplied password or username. In tests these events are
classified as `TEST`; normal application login failures are classified as
`REAL`. Alerts are not automatic containment actions and do not modify
PropertyChain.

## Simulation scenarios

Administrators can run the nine built-in scenarios from the Simulation page.
Each run is written atomically with its event records, actor, completion state,
and event count. The scenarios create local events classified `SIMULATED`,
which pass through the same detection evaluator as other incoming events.
They do not send network traffic, contact external systems, or execute
containment actions.

## Reports and settings

The Reports page reads current SQLite records for events, incidents, detection
rules, alerts and executions, monitoring sources, simulation runs, ingestion
jobs, response recommendations, evidence/custody records, and audit history.
Date, severity, classification, incident-status, record-status, and source
filters are applied where relevant. CSV export uses database rows, quotes
fields with Python's CSV writer, and prefixes formula-like cells to reduce
spreadsheet formula injection risk. Audit reports show at most the latest 1,000
matching entries. Browser printing uses the print stylesheet. SIMULATED and
TEST classifications remain distinct from REAL events.

The Settings page displays the signed-in user's profile and read-only system
information. Users can change their password only after supplying the current
password; new passwords follow the existing minimum length policy and are
stored as password hashes. Administrators can create analyst accounts and
update user roles or active state. Self-deactivation/demotion and removal of
the last active administrator are blocked. State-changing settings forms use
CSRF tokens and account changes are audited.

Incident recommendation permissions are enforced in routes and service
functions using the active database user's role. Administrators and analysts
can view incidents, register evidence, and record recommendations or
controlled-simulation metadata. Administrators alone can assign incidents,
change incident status, approve/cancel recommendations, or mark them
completed/cancelled. Analysts can only move an approved recommendation to
`in_progress`. The tests cover direct HTTP posts, direct service calls, CSRF,
and absence of database writes for rejected operations.

## Current implementation limits

Evidence can be registered as a text reference or uploaded from the supported
TXT, LOG, CSV, PDF, PNG, and JPEG formats (10 MB maximum). Uploads are stored
outside the public web directory, assigned a SHA-256 digest, and tracked in an
append-only custody history. Verification detects changes to stored bytes.
This is not malware scanning or an external cryptographic signature.

The ingestion service validates normalized adapter events, prevents duplicate
external references per source, writes events and detection results
transactionally, and records poll history. No production adapters are
registered, so manual polling currently records `unavailable`; it does not
fabricate successful collection. A controlled-simulation recommendation
records metadata and does not itself execute a simulation. Firebase and
Ethereum remain planned/not connected.

## Run the application

Set `PCSIRM_SECRET_KEY` in the environment (or in the project's `.env` file),
then run:

```powershell
python app.py
```

Session cookies are secure by default. For loopback-only HTTP development,
temporarily set `$env:PCSIRM_SESSION_COOKIE_SECURE = "false"` in PowerShell.
Keep secure cookies enabled behind HTTPS. See [DEMO_GUIDE.md](./DEMO_GUIDE.md)
for a presentation walkthrough and its safety limitations.
