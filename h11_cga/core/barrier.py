"""
H¹¹ Genesis — Control Barrier Certificate Engine
=================================================

Evaluates Control Barrier Functions (CBFs) to mathematically verify
forward-invariance of the allowable security manifold Ω_c:
    X_c(t_0) ∈ Ω_c ⟹ X_c(t) ∈ Ω_c  ∀ t ≥ t_0
"""

from __future__ import annotations

import logging
from typing import Dict, Any, Tuple

import numpy as np

from h11_cga.types import (
    SecurityState,
    SecurityBaseline,
    CGAConfig,
    NUM_DIMENSIONS,
)

logger = logging.getLogger(__name__)


class BarrierCertificate:
    """
    Control Barrier Certificate Evaluator for H¹¹-CGA.

    Defines the Control Barrier Function h(x):
        h(X_c) = 1.0 - ‖X_c - X_c*‖_W / r_max

    where:
        h(X_c) > 0  => Strictly inside permissible manifold Ω_c
        h(X_c) = 0  => At the boundary ∂Ω_c
        h(X_c) < 0  => Barrier breached (impermissible state)

    The Lie Derivative condition for forward-invariance is:
        dh/dt + γ_cbf · h(X_c) ≥ 0
    """

    def __init__(self, config: CGAConfig, cbf_gamma: float = 1.0) -> None:
        self.config = config
        self.cbf_gamma = cbf_gamma

    def compute_barrier_function(
        self, state: SecurityState, baseline: SecurityBaseline
    ) -> float:
        """
        Compute the scalar barrier value h(X_c).

        Args:
            state: Current SecurityState X_c(t).
            baseline: SecurityBaseline X_c*.

        Returns:
            Scalar h(X_c) where h >= 0 indicates safe/permitted state space.
        """
        # Distance from reference vector
        diff = state.vector - baseline.reference

        # Maximum allowable deviation radius before boundary breach
        max_radius = float(np.mean(baseline.upper_bound - baseline.lower_bound)) / 2.0
        if max_radius <= 0:
            max_radius = 0.3

        # Weighted L2 norm of deviation
        weights = self.config.dr_weights
        weighted_diff = diff * np.sqrt(weights)
        dist = float(np.linalg.norm(weighted_diff))

        # Normalized barrier function h(x) = 1 - (dist / max_radius)
        h_val = 1.0 - (dist / max_radius)
        return float(h_val)

    def verify_invariance(
        self,
        current_state: SecurityState,
        previous_state: SecurityState,
        baseline: SecurityBaseline,
        dt: float = 1.0,
    ) -> Tuple[bool, float, float]:
        """
        Verify the Control Barrier Function forward-invariance condition:
            dh/dt + γ_cbf · h(x) ≥ 0

        Args:
            current_state: State at time t.
            previous_state: State at time t - dt.
            baseline: Reference security baseline.
            dt: Time step duration.

        Returns:
            Tuple of (is_invariant, h_current, dh_dt_condition_val).
        """
        h_curr = self.compute_barrier_function(current_state, baseline)
        h_prev = self.compute_barrier_function(previous_state, baseline)

        # Finite difference derivative dh/dt
        dh_dt = (h_curr - h_prev) / (dt if dt > 0 else 1.0)

        # Barrier invariance condition: dh/dt + gamma * h(x) >= 0
        cbf_condition = dh_dt + (self.cbf_gamma * h_curr)
        is_invariant = (h_curr >= 0.0) and (cbf_condition >= 0.0)

        return is_invariant, h_curr, cbf_condition

    def evaluate_state_margin(
        self, state: SecurityState, baseline: SecurityBaseline
    ) -> Dict[str, Any]:
        """
        Evaluate per-dimension distance margins to the barrier boundary.
        """
        lower_margins = state.vector - baseline.lower_bound
        upper_margins = baseline.upper_bound - state.vector

        min_margin_lower = float(np.min(lower_margins))
        min_margin_upper = float(np.min(upper_margins))
        min_overall_margin = min(min_margin_lower, min_margin_upper)

        h_val = self.compute_barrier_function(state, baseline)

        return {
            "h_barrier": h_val,
            "is_safe": h_val >= 0.0,
            "min_margin": min_overall_margin,
            "per_dim_lower_margin": lower_margins,
            "per_dim_upper_margin": upper_margins,
        }
