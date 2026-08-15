"""
H¹¹ CONVERGE — Adaptive Cyber Response Engine
===============================================

Runs CCI cascade analysis and ΔCR prioritization to produce
ranked response actions for the security control loop.
"""

from __future__ import annotations

import logging
import numpy as np

from h11_cga.types import (
    DivergenceResult,
    HSAZone,
    ResponseAction,
    CascadePath,
    CGAConfig,
    NUM_DIMENSIONS,
)
from h11_cga.dcr_engine import DCREngine
from h11_cga.core.cci import CascadeAnalyzer

logger = logging.getLogger(__name__)


class ConvergeEngine:
    """H¹¹ CONVERGE — Adaptive Cyber Response Engine."""

    def __init__(self, config: CGAConfig) -> None:
        self.config = config
        self.dcr = DCREngine(config)
        self.cci = CascadeAnalyzer(config)

    def process(
        self,
        divergence: DivergenceResult,
        hsa_zone: HSAZone,
        cci_subcritical: bool,
        errors: np.ndarray,
    ) -> tuple[list[ResponseAction], float, bool, list[CascadePath]]:
        """Run CCI analysis, generate response plan.

        Returns:
            (actions, cci_value, cci_subcritical, cascade_paths)
        """
        cci_val = self.cci.compute_cci(errors)
        is_subcritical = self.cci.is_subcritical(cci_val)

        # Find cascade paths from the most divergent dimension
        cascade_paths: list[CascadePath] = []
        if errors.any():
            worst_dim = int(np.argmax(np.abs(errors)))
            cascade_paths = self.cci.identify_cascade_paths(worst_dim)

        # Generate prioritized response plan
        actions = self.dcr.generate_response_plan(
            divergence, hsa_zone, is_subcritical
        )

        return actions, cci_val, is_subcritical, cascade_paths

    def get_cascade_paths(self, source_dim: int) -> list[CascadePath]:
        """Get potential cascade paths from a specific source dimension."""
        return self.cci.identify_cascade_paths(source_dim)

    def reset(self) -> None:
        """Reset the CONVERGE engine."""
        self.dcr = DCREngine(self.config)
        self.cci = CascadeAnalyzer(self.config)
        logger.info("ConvergeEngine reset")
