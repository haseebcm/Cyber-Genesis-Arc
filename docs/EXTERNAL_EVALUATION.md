# External telemetry replay — 2026-10-10

Dataset: Splunk AWS IAM access-denied discovery events.
Source: https://research.splunk.com/attack_data/cc9b264f-efc9-11eb-926b-550bf0943fbb/
Download: https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1580/aws_iam_accessdenied_discovery_events/aws_iam_accessdenied_discovery_events.json
SHA-256: `4f52389f17745abf5fa1cf30c055d4f9d34022fcfb8e5c2544c70177da228433`

The publisher identifies this as attack-range simulation telemetry, not production
incident ground truth. All 1,150 records carry AccessDenied. The original generic
JSON adapter recognized zero records. With the explicit CloudTrail mapping it
recognizes 1,150 authorization-denial events, with zero queue drops.

This finding exposed and fixed a real ingestion schema gap. Recognition is not
malicious-incident detection: legitimate users can receive AccessDenied too. No
benign comparison, validated incident labels, or eleven-dimensional measurements
are supplied by this dataset. Therefore recall, false-positive rates, production
incident efficacy and cross-platform efficacy cannot be established from this replay.
No model score or physical validity claim is made.

To reproduce after downloading the source file:

```bash
python -m tools.replay_audit_logs downloaded.json --source-url https://research.splunk.com/attack_data/cc9b264f-efc9-11eb-926b-550bf0943fbb/
```

The raw third-party dataset is not redistributed in this repository.

# Intended Windows workstation acceptance

Run from this checkout on the intended workstation:

```powershell
python -m pip install ".[dev]"
python tools/windows_acceptance.py --output-dir acceptance-results
```

The runner targets disposable child processes only, and exits nonzero on any
failed, errored or skipped test. It records Windows/Python versions, JUnit counts,
and stdout/stderr. Review `acceptance-results/report.json`, `windows.xml`, and
`pytest.log`. Install Python before execution if the workstation does not have it.

CI runs the same acceptance suite on Windows/Python 3.12 and uploads evidence.
A GitHub-hosted runner is a reference environment, not the intended workstation.
Workstation acceptance remains pending until this command actually runs there.
The suite does not validate Windows service packaging, TLS/reverse proxy operation,
production sensor availability, workload SLOs, or malicious incident efficacy.
Do not convert those untested areas into passing claims.
