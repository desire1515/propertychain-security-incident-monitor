# PCSIRM Presentation Demonstration Guide

## Scope and safety

PCSIRM demonstrates local security-event processing, detection, incident
response recordkeeping, evidence integrity, controlled simulations, and
database-backed reports. It does not connect to PropertyChain, Firebase, or
Ethereum in the current configuration. Firebase and Ethereum sources are
planned and must remain disconnected until verified adapters and required
source configuration or ABI are available.

Use only a local demo database and benign sample files. Do not upload malware,
real credentials, production personal data, or sensitive customer evidence.
Uploaded evidence is kept outside the public web directory and hashed, but the
application does not provide malware scanning.

## Local startup

Run these commands from the project directory in PowerShell:

```powershell
$env:PCSIRM_SECRET_KEY = [guid]::NewGuid().ToString("N")
$env:PCSIRM_SESSION_COOKIE_SECURE = "false"
python app.py
```

Open `http://127.0.0.1:5000` in the same machine's browser and sign in with a
local PCSIRM account. The insecure-cookie override is for loopback HTTP
demonstrations only; do not use it on a shared network. Keep the Flask debug
mode disabled.

If the database already contains the intended demo account, do not run account
setup or database-reset commands. For a new local demo database only, visit the
application once to initialize its schema, stop the server with Ctrl+C, run
`python create_admin.py`, and start the application again. Enter the
administrator password through the hidden prompt; do not put it in a command,
script, or presentation.

Before the presentation, verify the local account can sign in and confirm the
current process is serving the expected PCSIRM checkout. Avoid running tests
while the application server is using the development database.

## Suggested walkthrough

1. **Dashboard and source status** — introduce the operational dashboard and
   show that Firebase and Ethereum sources are marked planned/not connected.
   Explain that manual administrative checks record notes and do not establish
   live connectivity.
2. **Simulation** — run a built-in controlled scenario. Open its generated
   events and confirm their `SIMULATED` classification. The scenario changes
   PCSIRM's local test records only; it does not modify PropertyChain.
3. **Detection and alert handling** — show a matching detection rule and the
   generated alert. Demonstrate acknowledgement, investigation, resolution,
   and the alert's recorded history.
4. **Incident workflow** — create an incident from a security event, assign it
   as an administrator, and walk through status changes and the incident
   timeline. Do not describe a response recommendation as an executed
   containment action.
5. **Evidence register** — register a benign text/log file (or a metadata-only
   reference), show its SHA-256 digest and custody entries, then run integrity
   verification. If the file was changed outside PCSIRM, show that verification
   reports a mismatch rather than silently accepting it.
6. **Response recommendations** — record a recommendation or controlled
   simulation note, demonstrate approval and investigation tracking according
   to role permissions, and show that this workflow records work rather than
   invoking external systems.
7. **Reports** — select a category, apply date/severity/classification or
   status/source filters, export the matching records as CSV, and use the print
   button. Point out that REAL, SIMULATED, and TEST records remain distinct.
8. **Settings** — show the signed-in profile and system-information section.
   As an administrator, demonstrate analyst-account management only if the
   presentation requires it; avoid changing or disabling the account used for
   the demo.

## Demo preparation checklist

- Confirm a working local admin account and, if useful, a separate analyst
  account.
- Prepare one benign `.txt`, `.log`, or `.csv` sample for evidence upload.
- Have one event with a matching enabled detection rule, or use the built-in
  simulation to generate a deterministic event.
- Confirm reports show the intended classifications and dates.
- Keep secrets out of screenshots, exported files, and presentation notes.
- Stop the local server with Ctrl+C after the walkthrough.

## Expected limitations to state

- No verified Firebase or Ethereum adapter is registered; external polling
  reports unavailable rather than success.
- A recorded manual source check is not a live health check.
- Simulations create classified local records and do not affect PropertyChain.
- Evidence hashing detects file changes but is not a malware scan or a
  cryptographic signature from an external trusted authority.
- Response recommendations are tracked and audited; PCSIRM does not execute
  containment or remediation actions against PropertyChain.
