"""
H¹¹ LIMIT — Universal Cyber Boundary Engine
=============================================

Runs ULE (limit utilization) and HSA (singularity approach) to determine
distance to failure and the current security zone.
"""

from __future__ import annotations

import logging
import numpy as np

from h11_cga.types import HSAZone, CGAConfig
from h11_cga.core.ule import LimitEngine as CoreLimitEngine
from h11_cga.core.hsa import SingularityTracker

logger = logging.getLogger(__name__)


class LimitEngine:
    """H¹¹ LIMIT — Universal Cyber Boundary Engine."""

    def __init__(self, config: CGAConfig) -> None:
        self.config = config
        self.core_ule = CoreLimitEngine(config)
        self.hsa = SingularityTracker(config)

    def evaluate(
        self, dr: float, divergence: np.ndarray
    ) -> tuple[float, HSAZone, float, float, bool]:
        """Run ULE + HSA analysis.

        Returns:
            (hsa_coordinate, hsa_zone, security_buffer, limit_utilization, within_limits)
        """
        # ULE: compute limit utilization from divergence as demand
        demand = np.abs(divergence)
        limit_utilization = self.core_ule.compute_limit_utilization(demand)
        within_limits = self.core_ule.is_within_limit(limit_utilization)

        # HSA: update buffer and compute singularity coordinate
        self.hsa.update_buffer(dr)
        hsa_coordinate = self.hsa.compute_singularity_coordinate(dr)
        hsa_zone = self.hsa.get_zone(hsa_coordinate)
        security_buffer = self.hsa.get_security_buffer()

        return hsa_coordinate, hsa_zone, security_buffer, limit_utilization, within_limits

    def get_time_to_boundary(self) -> float | None:
        """Estimate time to boundary crossing based on current trajectory."""
        return self.hsa.estimate_time_to_boundary()

    def reset(self) -> None:
        """Reset the LIMIT engine."""
        self.core_ule = CoreLimitEngine(self.config)
        self.hsa = SingularityTracker(self.config)
        logger.info("LimitEngine reset")
