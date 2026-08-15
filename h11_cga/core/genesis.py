"""
H¹¹ Genesis — Permission Operator
===================================

Implements the Genesis Permission Operator Π_c:
    x(t) permitted ⟺ x(t) ∈ Ω ∧ Φ(x) = 0 ∧ CCI(x) < Θ

Also provides the composite cyber permission:
    P_c = I · A · D · L · C
"""

from __future__ import annotations

import logging

import numpy as np

from h11_cga.types import CGAConfig, SecurityState, SecurityBaseline

logger = logging.getLogger(__name__)


class GenesisPermission:
    """Evaluates the Genesis Permission Operator (Π_c)."""

    def __init__(self, config: CGAConfig) -> None:
        self.config = config

    def compute_permission(
        self,
        state: SecurityState,
        baseline: SecurityBaseline,
        stability_violation: float,
        cci: float,
    ) -> float:
        """Compute Π_c — returns 1.0 if all three conditions are met, else 0.0.

        Conditions:
            1. State within envelope
            2. Stability violation Φ(x) = 0
            3. CCI < Θ_c
        """
        in_envelope = baseline.is_within_envelope(state)
        if in_envelope and stability_violation == 0.0 and cci < self.config.cci_threshold:
            return 1.0
        return 0.0

    def compute_stability_violation(
        self,
        state: SecurityState,
        baseline: SecurityBaseline,
    ) -> float:
        """Compute Φ(x) — magnitude of violation outside the envelope.

        Returns 0.0 if the state is within the envelope.
        """
        if baseline.is_within_envelope(state):
            return 0.0

        diff_lower = np.maximum(0, baseline.lower_bound - state.vector)
        diff_upper = np.maximum(0, state.vector - baseline.upper_bound)
        return float(np.linalg.norm(diff_lower + diff_upper))

    def compute_cyber_permission(
        self,
        identity_valid: float,
        auth_valid: float,
        domain_valid: float,
        limit_compliant: float,
        cascade_safe: float,
    ) -> float:
        """Compute composite cyber permission P_c = I · A · D · L · C."""
        permission = identity_valid * auth_valid * domain_valid * limit_compliant * cascade_safe
        return float(max(0.0, min(1.0, permission)))

    def evaluate(
        self,
        state: SecurityState,
        baseline: SecurityBaseline,
        cci: float,
    ) -> tuple[float, dict[str, float]]:
        """Convenience method — full permission evaluation with breakdown."""
        stability_violation = self.compute_stability_violation(state, baseline)
        permission = self.compute_permission(state, baseline, stability_violation, cci)

        details = {
            "stability_violation": stability_violation,
            "cci": cci,
            "cci_threshold": float(self.config.cci_threshold),
            "in_envelope": float(baseline.is_within_envelope(state)),
        }
        return permission, details
