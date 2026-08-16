"""
H¹¹-CGA Red-Team Benchmark Subpackage
======================================

Exports RedTeamBenchmarkEngine, AdvancedChallenge, ChallengeScenarioResult, and ChallengeReport.
"""

from h11_cga.benchmarks.redteam_engine import (
    RedTeamBenchmarkEngine,
    ScenarioResult,
    BenchmarkReport,
)
from h11_cga.benchmarks.challenge import (
    AdvancedChallenge,
    ChallengeScenarioResult,
    ChallengeReport,
)

__all__ = [
    "RedTeamBenchmarkEngine",
    "ScenarioResult",
    "BenchmarkReport",
    "AdvancedChallenge",
    "ChallengeScenarioResult",
    "ChallengeReport",
]
