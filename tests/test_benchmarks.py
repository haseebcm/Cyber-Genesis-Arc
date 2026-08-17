"""
H¹¹-CGA Phase 3 Red-Team Benchmark Unit Tests
==============================================
Tests for RedTeamBenchmarkEngine.
"""

import pytest

from h11_cga import (
    RedTeamBenchmarkEngine,
    BenchmarkReport,
    ScenarioResult,
)


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
