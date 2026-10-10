"""Measure ingestion coverage of external JSONL without inventing incident labels."""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from h11_cga.adapters.log_adapter import LogAdapter


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset', type=Path)
    parser.add_argument('--source-url', required=True)
    args = parser.parse_args()
    digest, total, recognized, types = hashlib.sha256(), 0, 0, Counter()
    adapter = LogAdapter()
    with args.dataset.open('rb') as stream:
        for line in stream:
            digest.update(line)
            if not line.strip():
                continue
            record = json.loads(line)
            total += 1
            event = adapter.ingest_json_log(record)
            if event:
                recognized += 1
                types[event.event_type] += 1
            adapter.collect()
    print(json.dumps(dict(source_url=args.source_url,sha256=digest.hexdigest(),records=total,recognized=recognized,unrecognized=total-recognized,event_types=dict(types),dropped=adapter.dropped_events,scope='Schema recognition only; no incident ground truth or benign comparison. Not a detection/false-positive rate.'),indent=2))


if __name__ == '__main__':
    main()
