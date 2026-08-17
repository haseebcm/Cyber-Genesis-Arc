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
        self._calibration_samples: list[np.ndarray] = []

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

    @property
    def is_calibrating(self) -> bool:
        """Whether SENSE is still learning the baseline from observations."""
        window = getattr(self.config, "baseline_calibration_ticks", 0)
        return window > 0 and len(self._calibration_samples) < window

    def observe_for_calibration(self, state: SecurityState) -> bool:
        """
        Fold an observed state into the learned baseline X_c*.

        Live systems never idle at the ideal all-nominal vector, so during
        the warmup window the reference is the running mean of observation
        and the envelope is derived from observed variance. Returns True
        while calibration is still in progress.
        """
        window = getattr(self.config, "baseline_calibration_ticks", 0)
        if window <= 0 or len(self._calibration_samples) >= window:
            return False

        self._calibration_samples.append(np.asarray(state.vector, dtype=np.float64).copy())
        samples = np.vstack(self._calibration_samples)

        reference = samples.mean(axis=0)
        sigma = samples.std(axis=0) if len(self._calibration_samples) > 1 else np.zeros(NUM_DIMENSIONS)
        tolerance = np.maximum(
            self.config.baseline_tolerance_sigmas * sigma,
            self.config.baseline_min_tolerance,
        )

        self.state_space.update_baseline(reference, tolerance=tolerance)

        still_calibrating = len(self._calibration_samples) < window
        if not still_calibrating:
            logger.info(
                f"Baseline calibrated over {window} observations: "
                f"reference={np.round(reference, 3).tolist()}"
            )
        return still_calibrating

    def get_state_space(self) -> SecurityStateSpace:
        """Get the underlying MCC state space tracker."""
        return self.state_space

    def reset(self) -> None:
        """Reset the SENSE engine to the nominal secure state."""
        self.state_space.reset()
        self._calibration_samples.clear()
        logger.info("SenseEngine reset")
