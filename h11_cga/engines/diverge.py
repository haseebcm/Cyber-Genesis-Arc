"""
H¹¹ DIVERGE — Cyber Divergence Intelligence Engine
====================================================

Runs DSA directional divergence analysis and DR magnitude computation
to produce behavioral trajectory classification.
"""

from __future__ import annotations

import logging

from h11_cga.types import (
    SecurityState,
    SecurityBaseline,
    DivergenceResult,
    DivergenceClassification,
    CGAConfig,
)
from h11_cga.core.dsa import DirectionalDivergence
from h11_cga.core.dr import DivergenceRatio

logger = logging.getLogger(__name__)


class DivergeEngine:
    """H¹¹ DIVERGE — Cyber Divergence Intelligence Engine."""

    def __init__(self, config: CGAConfig) -> None:
        self.config = config
        self.dsa = DirectionalDivergence(config)
        self.dr = DivergenceRatio(config)
        self.classification = DivergenceClassification.NORMAL

    def analyze(
        self,
        state: SecurityState,
        baseline: SecurityBaseline,
        domain_metric: float = 1.0,
        dt: float = 1.0,
    ) -> tuple[DivergenceResult, float, float, float]:
        """Run DSA + DR analysis.

        Domain metric W_c(a) from DNT produces the architecture term
        DR_c^(a) = W_c(a) · DR_c.

        Returns:
            (divergence_result, dr_value, dr_adjusted, dr_rate)
        """
        div_result = self.dsa.compute_divergence(state, baseline, dt=dt)

        dr_value = self.dr.compute_dr(div_result.divergence_vector)
        self.dr.record(dr_value)

        dr_adjusted = self.dr.compute_domain_adjusted_dr(dr_value, domain_metric)
        dr_rate = self.dr.get_dr_rate(dt=dt)

        self.classification = div_result.classification

        return div_result, dr_value, dr_adjusted, dr_rate

    def get_behavioral_state(self) -> DivergenceClassification:
        """Get current divergence classification."""
        return self.classification

    def reset(self) -> None:
        """Reset the DIVERGE engine."""
        self.dsa = DirectionalDivergence(self.config)
        self.dr = DivergenceRatio(self.config)
        self.classification = DivergenceClassification.NORMAL
        logger.info("DivergeEngine reset")
