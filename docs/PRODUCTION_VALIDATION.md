# Production validation and acceptance

Status: production certification is incomplete. Passing CI is code-behaviour evidence,
not a claim of detection efficacy or universal security. H11 dimensionality, operators,
and the control loop are preserved.

## Evidence available

The 4.2 commit passed eight GitHub CI jobs: Ubuntu/Windows, Python 3.10–3.13,
coverage gate, builds, installed wheel and dashboard asset checks. Real response
integration tests cover disposable children only: suspend/resume, policy denial,
durable journal, PID identity, restart recovery and service-crash rollback.
Those tests skip when host procfs and execution namespaces differ. A skip is not
successful OS remediation validation.

The new replay evaluator computes TP/TN/FP/FN, recall, precision, false-positive
rate, and first detection sample. It records the dataset SHA-256. It never feeds
labels into the engine or calls attack injection. Regression data is synthetic
and establishes evaluator correctness only.

## Independent incident evaluation

Collect separately labelled benign and malicious episodes in an authorized lab
representative of the intended workloads. Separate calibration/training data
from held-out evaluation data. Record collector version, host configuration,
incident ground truth, mapping definitions, sampling interval, and source records.
Calibration arrays must contain benign observations. Analysts must independently
verify labels and mappings; the evaluator cannot verify these facts.

JSONL input: one object per independent episode, with `id`, `malicious` (boolean),
`source`, `calibration` (at least 20 samples), and `samples` (one or more). Each
sample contains every lowercase dimension name and a finite value in [0,1].
Do not fill missing observations with nominal values to pass validation.
Authorization requires access-policy evidence, Trust requires integrity/attestation
or a documented behavioural source, and Governance requires policy/configuration
evidence. Host counters alone do not measure them.

Choose alert threshold and acceptable recall/FPR before held-out evaluation.
For example, the following rates are illustrative, not universal requirements:

```bash
python -m h11_cga.benchmarks.validation held-out.jsonl \
  --threshold 0.4 --min-recall 0.95 --max-fpr 0.01 > evaluation.json
```

The command exits nonzero if its rates fail. Tiny datasets cannot establish these
rates reliably. Report sample sizes and statistical uncertainty; evaluate each
workload and incident class separately. Detection sample indices are not wall-clock
latency. Replay does not exercise collectors, HTTP service, TLS or OS remediation.

## Load and recovery

```bash
python -m examples.validation_soak --ticks 10000 --workers 4
python -m pytest tests/test_real_response.py -q
```

The soak exercises serialized concurrent engine calls, finite scores and bounded
assessment/event histories. Its latency includes lock contention. It is an
in-process synthetic check, not HTTP load acceptance or a memory-leak proof.
Run deployment-specific authenticated HTTP load, sensor outage, disk-full,
journal corruption, privilege-loss, process exit, service kill/restart, and rollback
failure exercises in an isolated staging environment. Preserve logs and outcome
observations. Do not suspend production processes for testing.

Log ingestion now bounds pending events and exposes `dropped_events`. Monitor that
counter; overflow discards the oldest event and means evidence was lost. Install
reliable upstream collection/backpressure and alerting appropriate to the deployment.

## Release gate

Before production acceptance, obtain:

- Held-out incident and benign-workload results meeting predeclared rates, with
  sufficient independent samples and reviewed mappings for all claimed dimensions.
- Target-platform response/recovery evidence with no unexplained skips or failures.
- Load/availability evidence meeting the deployment SLOs and verified backup recovery.
- Independent security review and remediation of its blocking findings.
- Named operational owner, TLS/access controls, retention, rollback procedure,
  dependency maintenance and an approved incident response runbook.

Record reviewer identity, evidence hashes, deployment scope and approval date.
An automated test cannot supply independent reviewer approval or demonstrate the
physical validity of the H11 axioms. Do not call an incomplete gate production validated.
