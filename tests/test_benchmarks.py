"""
H¹¹-CGA Phase 3 Red-Team Benchmarks & Barrier Unit Tests
==========================================================
Tests for BarrierCertificate and RedTeamBenchmarkEngine.
"""

import pytest
import numpy as np

from h11_cga import (
    SecurityState,
    SecurityBaseline,
    CGAConfig,
    BarrierCertificate,
    RedTeamBenchmarkEngine,
    BenchmarkReport,
    ScenarioResult,
    NUM_DIMENSIONS,
)


def test_barrier_certificate_computation():
    config = CGAConfig()
    cert = BarrierCertificate(config, cbf_gamma=1.0)

    baseline = SecurityBaseline(
        reference=np.ones(NUM_DIMENSIONS),
        lower_bound=np.full(NUM_DIMENSIONS, 0.7),
        upper_bound=np.ones(NUM_DIMENSIONS),
    )

    state_nominal = SecurityState(vector=np.ones(NUM_DIMENSIONS))
    h_nominal = cert.compute_barrier_function(state_nominal, baseline)
    assert h_nominal == 1.0

    state_degraded = SecurityState(vector=np.full(NUM_DIMENSIONS, 0.5))
    h_degraded = cert.compute_barrier_function(state_degraded, baseline)
    assert h_degraded < 0.5


def test_barrier_invariance_verification():
    config = CGAConfig()
    cert = BarrierCertificate(config, cbf_gamma=1.0)

    baseline = SecurityBaseline(
        reference=np.ones(NUM_DIMENSIONS),
        lower_bound=np.full(NUM_DIMENSIONS, 0.7),
        upper_bound=np.ones(NUM_DIMENSIONS),
    )

    state_t1 = SecurityState(vector=np.ones(NUM_DIMENSIONS))
    state_t2 = SecurityState(vector=np.full(NUM_DIMENSIONS, 0.95))

    is_inv, h_curr, cbf_val = cert.verify_invariance(state_t2, state_t1, baseline, dt=1.0)
    assert is_inv is True
    assert h_curr > 0.0


def test_redteam_benchmark_engine():
    engine = RedTeamBenchmarkEngine()
    scenario_res = engine.run_scenario(0)
    assert isinstance(scenario_res, ScenarioResult)
    assert scenario_res.h11_detected is True
    assert scenario_res.detection_speedup_ratio > 1.0

    report = engine.run_full_benchmark()
    assert isinstance(report, BenchmarkReport)
    assert report.total_scenarios == 10
    assert report.h11_detection_rate_pct >= 90.0
    assert report.avg_speedup_ratio > 1.0
