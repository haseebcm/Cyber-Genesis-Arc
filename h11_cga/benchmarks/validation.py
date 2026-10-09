"""Replay independently labelled, normalized telemetry without model injection.

Each JSONL record is one independent episode with id, malicious (bool), source,
calibration (benign samples), and samples (evaluation samples). Every sample
must supply all eleven normalized coordinates. Labels never enter the engine.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

from h11_cga.orchestrator import CyberGenesisEngine
from h11_cga.types import CGAConfig, DIMENSION_NAMES, TelemetryInput


def _sample(value):
    if not isinstance(value, dict) or set(value) != {n.lower() for n in DIMENSION_NAMES}:
        raise ValueError('Every sample must explicitly provide all eleven dimensions')
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or not 0 <= v <= 1 for v in value.values()):
        raise ValueError('Coordinates must be finite numbers in [0,1]')
    return value


def evaluate(episodes, threshold=0.4):
    if not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError('Threshold must be in [0,1]')
    counts = dict(tp=0, tn=0, fp=0, fn=0)
    results, ids = [], set()
    for episode in episodes:
        identity = episode.get('id')
        if not isinstance(identity, str) or not identity or identity in ids:
            raise ValueError('Episode identifiers must be unique nonempty strings')
        ids.add(identity)
        label = episode.get('malicious')
        if type(label) is not bool or not isinstance(episode.get('source'), str) or not episode['source']:
            raise ValueError('Boolean label and evidence source required')
        calibration, samples = episode.get('calibration'), episode.get('samples')
        if not isinstance(calibration, list) or len(calibration) < 20 or not isinstance(samples, list) or not samples:
            raise ValueError('At least twenty benign calibration samples and one evaluation sample required')
        engine = CyberGenesisEngine(CGAConfig(baseline_calibration_ticks=len(calibration), closed_loop_enabled=False))
        for tick, sample in enumerate(calibration):
            engine.process_tick(TelemetryInput(raw_values=_sample(sample), timestamp=float(tick+1)))
        scores = [engine.process_tick(TelemetryInput(raw_values=_sample(sample), timestamp=float(len(calibration)+i+1))).genesis_value for i, sample in enumerate(samples)]
        first = next((i for i, score in enumerate(scores) if score < threshold), None)
        detected = first is not None
        counts['tp' if label and detected else 'fn' if label else 'fp' if detected else 'tn'] += 1
        results.append(dict(id=identity, source=episode['source'], malicious=label, detected=detected, detection_sample=first, minimum_score=min(scores)))
    positives, negatives = counts['tp']+counts['fn'], counts['tn']+counts['fp']
    if not positives or not negatives:
        raise ValueError('Both malicious and benign episodes are required')
    return dict(threshold=threshold, counts=counts, recall=counts['tp']/positives, false_positive_rate=counts['fp']/negatives, precision=counts['tp']/(counts['tp']+counts['fp']) if counts['tp']+counts['fp'] else 0, episodes=results, limitation='Labels, provenance, sensor mappings and dataset independence require external review; this report is not production certification.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset', type=Path)
    parser.add_argument('--threshold', type=float, default=0.4)
    parser.add_argument('--min-recall', type=float, required=True)
    parser.add_argument('--max-fpr', type=float, required=True)
    args = parser.parse_args()
    if not 0 <= args.min_recall <= 1 or not 0 <= args.max_fpr <= 1:
        parser.error('Acceptance rates must be in [0,1]')
    raw = args.dataset.read_bytes()
    report = evaluate([json.loads(line) for line in raw.splitlines() if line.strip()], args.threshold)
    report['dataset_sha256'] = hashlib.sha256(raw).hexdigest()
    report['accepted'] = report['recall'] >= args.min_recall and report['false_positive_rate'] <= args.max_fpr
    print(json.dumps(report, indent=2, allow_nan=False))
    raise SystemExit(0 if report['accepted'] else 1)


if __name__ == '__main__':
    main()
