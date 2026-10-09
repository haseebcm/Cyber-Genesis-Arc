"""Concurrent model soak; does not measure HTTP or deployment capacity."""
import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor
import numpy as np
from h11_cga import CyberGenesisEngine
from h11_cga.types import CGAConfig, DIMENSION_NAMES, TelemetryInput


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ticks', type=int, default=10000)
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    if args.ticks < 1 or args.workers < 1:
        parser.error('Positive ticks and workers required')
    engine = CyberGenesisEngine(CGAConfig(history_limit=100, closed_loop_enabled=False))
    sample = {name.lower(): 0.9 for name in DIMENSION_NAMES}
    def tick(_):
        start = time.perf_counter()
        result = engine.process_tick(TelemetryInput(raw_values=sample))
        if not np.isfinite(result.genesis_value):
            raise RuntimeError('Nonfinite assessment')
        return time.perf_counter()-start
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        durations = list(pool.map(tick, range(args.ticks)))
    elapsed = time.perf_counter()-start
    if len(engine._assessment_history) > 100 or len(engine._event_log) > 100:
        raise RuntimeError('History bound exceeded')
    print(json.dumps(dict(ticks=args.ticks, workers=args.workers, seconds=elapsed, ticks_per_second=args.ticks/elapsed, p95_ms=float(np.percentile(durations,95)*1000), retained_assessments=len(engine._assessment_history), scope='Concurrent in-process synthetic soak; not deployment acceptance'), indent=2))


if __name__ == '__main__':
    main()
