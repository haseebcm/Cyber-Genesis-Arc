"""Run on the intended Windows host; no production PIDs are targeted.

Requires the repository's dev dependencies. Disposable child processes only.
Successful completion validates listed behaviours, not incident detection efficacy.
"""
import argparse
import json
import platform
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=Path('acceptance-results'))
    args = parser.parse_args()
    if sys.platform != 'win32':
        parser.error('This acceptance run must execute on the intended Windows host')
    root = Path(__file__).resolve().parents[1]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    junit = output/'windows.xml'
    # Prevent an interrupted rerun from reporting stale successful evidence.
    junit.unlink(missing_ok=True)
    selected = ['tests/test_real_response.py', 'tests/test_hardening.py', 'tests/test_validation.py']
    result = subprocess.run([sys.executable,'-m','pytest',*selected,'-q',f'--junitxml={junit}'],cwd=root,capture_output=True,text=True,timeout=180)
    (output/'pytest.log').write_text(result.stdout+'\n'+result.stderr,encoding='utf-8')
    suites = ET.parse(junit).getroot().iter('testsuite') if junit.exists() else []
    counts = {key:0 for key in ['tests','failures','errors','skipped']}
    for suite in suites:
        for key in counts:
            counts[key] += int(suite.get(key,0))
    accepted = result.returncode == 0 and counts['tests'] > 0 and not any(counts[k] for k in ['failures','errors','skipped'])
    report = dict(accepted=accepted, platform=platform.platform(), python=sys.version, counts=counts, scope='Local HTTP controls, ingestion, disposable-child response and crash rollback; not TLS, production workload or incident efficacy')
    (output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
    raise SystemExit(0 if accepted else 1)


if __name__ == '__main__':
    main()
