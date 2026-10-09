# Windows operation and live presentation

This release provides actual Windows host monitoring, registered AI tool enforcement,
and operator-controlled suspension/resumption of explicitly configured user processes.
It does not claim automatic malware attribution, malware removal, or Windows kernel
packet enforcement. Model simulation remains a separate, labelled mode.

## Installation (PowerShell)

Install Python 3.12 from python.org, extract the source package, and open PowerShell in
its directory. The commands below do not require activation or execution-policy changes.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe examples\live_response_demo.py
```

The live demonstration creates a disposable process writing a heartbeat, actually
suspends it through the operating system, verifies that the heartbeat stops, then
verifies that automatic rollback resumes it. It never targets existing applications.
This demonstrates real enforcement rather than a changed model score.

## Host monitoring

```powershell
.\.venv\Scripts\python.exe -m h11_cga.cli_server
```

Open http://127.0.0.1:8080. Allow 20 samples for baseline calibration. Linux-only
procfs probes are skipped on Windows. Sensor provenance identifies which coordinates
were observed. There is no kernel eBPF program on Windows.

## Enable real response controls

Choose a disposable application or a workload explicitly approved for temporary
suspension. Get its PID from Task Manager's Details tab. Do not select system processes
or services; the controller refuses its own process, ancestors, PID 1, other users,
and already suspended targets. Restrict the journal folder to your Windows account.

```powershell
$env:H11_API_TOKEN = & .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
$journal = Join-Path $env:LOCALAPPDATA 'H11-CGA\responses.sqlite3'
.\.venv\Scripts\python.exe -m h11_cga.cli_server --allow-pid 12345 --audit-path $journal --max-hold 30
```

Replace `12345` with the approved PID. The policy pins its creation time at startup,
so a later process reusing the PID is not targeted. Multiple `--allow-pid` options
are supported, with at most 32 targets. API authentication is mandatory for response
mode. The dashboard provides approved target buttons and an audit trail.

API operations use `Authorization: Bearer <token>`:

- `GET /api/v1/responses`: policy targets, active responses, recent journal events.
- `POST /api/v1/responses/quarantine`: JSON `{"pid":12345,"reason":"approved containment","hold_seconds":10}`.
- `POST /api/v1/responses/resume`: JSON `{"response_id":"<id returned by quarantine>"}`.

Each action writes a durable intent before suspension, verifies the OS outcome, and
records the result. A detached watchdog must acknowledge startup before suspension;
it resumes the process at the deadline even if the service exits abruptly. A crash
between suspension and journal confirmation has an additional recovery grace period
of up to 10 seconds. Startup recovery resumes unfinished actions against their original
identities. Journal access/OS permission failures are reported rather than treated as
success. Manual early resume and normal service shutdown also release active targets.

Stop with Ctrl+C. Back up the journal while the service is stopped; SQLite WAL files
are part of an active journal. Keep its folder private and use disk encryption where
required. A compromised service account can interfere with the service and watchdog;
these are user-space controls, not an anti-tamper driver. Only one service instance
should operate a journal, and the watchdog requires the same installed Python environment.
Network access requires TLS termination and restricted firewall rules as described in
DEPLOYMENT.md. Local HTTP is the default.

## Supported claim

“Working Windows monitoring and controlled process containment with verified rollback,
durable audit, and policy-gated AI tools” accurately describes the implemented scope.
Production use additionally requires acceptance tests on the actual customer workload,
operational ownership, backups, and a reviewed response policy. Do not present synthetic
scenario scores as measured antivirus or EDR performance.
