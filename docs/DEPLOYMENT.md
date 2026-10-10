# H11-CGA deployment and presentation

## Presentation tomorrow

Python 3.10 or later is required. From this repository:

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell alternative: .venv\Scripts\Activate.ps1
python -m pip install ".[dev]"
python -m pytest -q
python examples/presentation_demo.py
h11-server --demo
```

Open http://127.0.0.1:8080. Demo mode runs the H11 model without host telemetry. Inject ransomware, inspect the state dimensions and recommended responses, then apply model projection. All attack and recovery controls affect the simulation only. The dashboard runs offline and needs no external account.

Use `h11-server` without `--demo` for actual host monitoring. This learns the baseline over 20 samples, polls once per second, and disables mutation endpoints. Status reads do not advance the model. Missing measurements retain their previous coordinates; inspect provenance and skipped adapters instead of assuming every dimension is observed. Alert scores during calibration are provisional.

## Secure deployment

The service binds to loopback by default. To bind elsewhere, supply a random bearer token of at least 32 characters in `H11_API_TOKEN`; do not put tokens in command-line arguments or commit them. Generate one with Python's `secrets.token_urlsafe(48)`. The dashboard asks for the token and retains it in the current browser session.

For network deployment, place the service behind a TLS reverse proxy, restrict access with a firewall, and keep the backend port private. The built-in service speaks HTTP and does not itself provide TLS. Run as an unprivileged dedicated user; telemetry requiring unavailable privileges is skipped. Keep demo mode local. `/healthz` is a process liveness endpoint, not evidence that all sensors are healthy.

History and audit memory are bounded to 1,000 items by default. Forward application logs to your deployment's log collector for durable retention. The current HMAC state key is randomly generated for each service instance; consumers needing stable verification must inject a separately managed secret into `StateIntegrityProver`. This HMAC is not an externally certified attestation system.

## AI integration

Register each callable with its trusted category and a parameter validator before calling `execute_guarded`. Validators should implement concrete allowlists for paths, destinations, database operations, and arguments. Unknown tools, mismatched categories, replacement callables, failed validators, and denied Genesis permission fail closed. Projection is isolated from observed state; record actual outcomes through trusted telemetry separately. Inspection alone does not prevent execution outside the wrapper.

The prompt filter is a keyword heuristic. It is not a semantic safety guarantee. Swarm request accounting uses a 60-second window and a bounded registry; callers must handle registry-capacity rejection. Put agent identities and authorization outside untrusted model output.

## Claims supported by this package

Implemented: eleven-dimensional state scoring, authored cascade model, origin hypotheses, coherence audits, H11 law scoring, real host counters, secured local monitoring, isolated AI proposal scoring, and explicit tool policies.

Real response: explicitly allowlisted process suspension/resumption, durable SQLite journaling, restart recovery, and a detached deadline watchdog. See WINDOWS.md for configuration.

Simulated: attack injection, algebraic recovery, and XDP packet blocking. No kernel eBPF program is loaded. External product comparisons are unavailable.

Still required before a production-security claim: labelled incident and benign-workload evaluation, false-positive/false-negative measurements, workload-specific calibration, target-environment verification of process remediation and rollback, deployment load tests, external security review, and operational recovery procedures. Unit tests validate code behavior; they do not establish detection efficacy or H11 physical axioms.

See [production validation](PRODUCTION_VALIDATION.md) for evidence requirements and replay tooling.

## Control-plane availability and origin policy

GET responses are snapshotted under the runtime lock and written to the client after
releasing it, so slow readers do not hold the telemetry lock. Connection concurrency
remains bounded to 32 with a five-second socket timeout.

Host headers must match the bound hostname and port. For a TLS reverse proxy or
wildcard bind, configure `H11_PUBLIC_ORIGIN=https://security.example.com` with the
exact external origin (no trailing slash/path). The proxy must forward that Host.
Arbitrary Host headers and browser origins are refused, including on loopback.
Remote binding still requires a bearer token and a private backend listener.

`/readyz` now returns 503 when required dimensions are missing from the latest
collection, calibration is incomplete, sampling is stale/failing, or response
recovery has failed. Its body lists reasons and missing dimensions. Default required
measurements are the eight host dimensions. Use repeated `--require-dimension`
options to declare the actual deployment contract. Requiring authorization, trust,
and governance will keep readiness false until trusted collectors supply them.
Reducing requirements narrows the coverage claim; it does not establish 11-dimensional
observation. Simulation readiness is explicitly marked with mode `simulation`.
