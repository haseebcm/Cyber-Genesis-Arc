"""
H¹¹ SENSE — Security State & Environment Normalization System
===============================================================

Ingests raw telemetry and security events, normalizes them into
the 11-dimensional MCC security state space, and maintains the
baseline reference state.
"""

from __future__ import annotations

import logging
import time

import numpy as np

from h11_cga.types import (
    SecurityState,
    SecurityBaseline,
    TelemetryInput,
    CGAConfig,
    NUM_DIMENSIONS,
    DIMENSION_INDEX,
)
from h11_cga.core.mcc import SecurityStateSpace

logger = logging.getLogger(__name__)


class SenseEngine:
    """H¹¹ SENSE — Security State & Environment Normalization System."""

    def __init__(self, config: CGAConfig) -> None:
        self.config = config
        self.state_space = SecurityStateSpace(config)

        # Default: nominal state (all 1.0) with envelope [0.7, 1.0]
        self.current_state = SecurityState(
            vector=np.ones(NUM_DIMENSIONS), timestamp=time.time()
        )
        self.baseline = SecurityBaseline(
            reference=np.ones(NUM_DIMENSIONS),
            lower_bound=np.full(NUM_DIMENSIONS, 0.7),
            upper_bound=np.ones(NUM_DIMENSIONS),
        )

    def ingest(self, telemetry: TelemetryInput) -> SecurityState:
        """Normalize telemetry into state, apply events, update state space."""
        vec = self.current_state.vector.copy()

        # Map raw values to dimensions
        for key, value in telemetry.raw_values.items():
            key_lower = key.lower()
            if key_lower in DIMENSION_INDEX:
                vec[DIMENSION_INDEX[key_lower]] = float(value)

        # Apply event impacts
        for event in telemetry.events:
            vec = vec + event.impact

        # Clamp to [0, 1]
        vec = np.clip(vec, 0.0, 1.0)

        new_state = SecurityState(vector=vec, timestamp=telemetry.timestamp)
        self.current_state = new_state
        self.state_space.update_state(new_state)
        return new_state

    def get_current_state(self) -> SecurityState:
        """Get the current security state."""
        return self.current_state

    def get_baseline(self) -> SecurityBaseline:
        """Get the current security baseline."""
        return self.baseline

    def update_baseline(
        self, reference: np.ndarray, tolerance: float = 0.3
    ) -> None:
        """Update the security baseline with a new reference and tolerance."""
        if reference.shape != (NUM_DIMENSIONS,):
            raise ValueError(f"Reference must have shape ({NUM_DIMENSIONS},)")

        self.baseline = SecurityBaseline(
            reference=reference.copy(),
            lower_bound=reference - tolerance,
            upper_bound=np.minimum(reference + tolerance, np.ones(NUM_DIMENSIONS)),
        )
        logger.debug("Baseline updated")

    def get_state_space(self) -> SecurityStateSpace:
        """Get the underlying state space tracker."""
        return self.state_space

    def reset(self) -> None:
        """Reset the SENSE engine state."""
        self.current_state = SecurityState(
            vector=np.ones(NUM_DIMENSIONS), timestamp=time.time()
        )
        self.baseline = SecurityBaseline(
            reference=np.ones(NUM_DIMENSIONS),
            lower_bound=np.full(NUM_DIMENSIONS, 0.7),
            upper_bound=np.ones(NUM_DIMENSIONS),
        )
        self.state_space = SecurityStateSpace(self.config)
        logger.info("SenseEngine reset")
