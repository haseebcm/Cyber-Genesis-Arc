"""
H¹¹ SENSE — Security State & Environment Normalization System
===============================================================

Ingests raw telemetry and security events, normalizes them into
the 11-dimensional MCC security state space, and maintains the
baseline reference state.

MCC is the single source of truth for X_c(t) and X_c*.
"""

from __future__ import annotations

import logging

import numpy as np

from h11_cga.types import (
    SecurityState,
    SecurityBaseline,
    TelemetryInput,
    CGAConfig,
    NUM_DIMENSIONS,
)
from h11_cga.core.mcc import SecurityStateSpace

logger = logging.getLogger(__name__)


class SenseEngine:
    """H¹¹ SENSE — Security State & Environment Normalization System."""

    def __init__(self, config: CGAConfig) -> None:
        self.config = config
        self.state_space = SecurityStateSpace(config)

    @property
    def current_state(self) -> SecurityState:
        return self.state_space.current_state

    @current_state.setter
    def current_state(self, state: SecurityState) -> None:
        self.state_space.update_state(state)

    @property
    def baseline(self) -> SecurityBaseline:
        return self.state_space.baseline

    @baseline.setter
    def baseline(self, baseline: SecurityBaseline) -> None:
        self.state_space.baseline = baseline

    def ingest(self, telemetry: TelemetryInput) -> SecurityState:
        """Normalize telemetry into MCC state, apply events, update history."""
        return self.state_space.apply_telemetry(telemetry)

    def get_current_state(self) -> SecurityState:
        """Get the current security state."""
        return self.state_space.current_state

    def get_baseline(self) -> SecurityBaseline:
        """Get the current security baseline."""
        return self.state_space.baseline

    def update_baseline(
        self, reference: np.ndarray, tolerance: float = 0.3
    ) -> None:
        """Update the security baseline with a new reference and tolerance."""
        if np.asarray(reference).shape != (NUM_DIMENSIONS,):
            raise ValueError(f"Reference must have shape ({NUM_DIMENSIONS},)")
        self.state_space.update_baseline(reference, tolerance=tolerance)
        logger.debug("Baseline updated")

    def get_state_space(self) -> SecurityStateSpace:
        """Get the underlying MCC state space tracker."""
        return self.state_space

    def reset(self) -> None:
        """Reset the SENSE engine to the nominal secure state."""
        self.state_space.reset()
        logger.info("SenseEngine reset")
