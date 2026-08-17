from __future__ import annotations

import time

import numpy as np

from h11_cga.types import (
    CGAConfig,
    SecurityState,
    SecurityBaseline,
    DivergenceResult,
    DivergenceClassification,
    NUM_DIMENSIONS,
)


class DirectionalDivergence:
    """
    DSA - Directional Security Divergence Engine.

    Computes D_c(t) = X_c(t) - X_c* and tracks magnitude, acceleration,
    and trajectory classification (NORMAL / RECOVERING / ESCALATING).
    """

    def __init__(self, config: CGAConfig):
        self.config = config
        self._divergence_history: list[np.ndarray] = []
        self._timestamp_history: list[float] = []

    def compute_divergence(
        self,
        current: SecurityState,
        baseline: SecurityBaseline,
        dt: float = 1.0,
    ) -> DivergenceResult:
        """Compute divergence D_c(t) = X_c(t) - X_c* with time-aware acceleration."""
        divergence_vector = current.vector - baseline.reference
        magnitude = self.get_divergence_magnitude(divergence_vector)
        now = current.timestamp if current.timestamp else time.time()

        # Record current sample first so acceleration includes this tick
        self._divergence_history.append(divergence_vector)
        self._timestamp_history.append(now)

        window_size = getattr(self.config, "dsa_history_window", 100)
        if len(self._divergence_history) > window_size:
            self._divergence_history = self._divergence_history[-window_size:]
            self._timestamp_history = self._timestamp_history[-window_size:]

        acceleration_vector = self.get_acceleration(dt)
        acceleration_magnitude = float(np.linalg.norm(acceleration_vector))

        if len(self._divergence_history) > 1:
            prev_magnitude = self.get_divergence_magnitude(self._divergence_history[-2])
            mag_derivative = magnitude - prev_magnitude
        else:
            mag_derivative = 0.0

        classification = self.classify(magnitude, mag_derivative)

        return DivergenceResult(
            divergence_vector=divergence_vector,
            acceleration_vector=acceleration_vector,
            magnitude=magnitude,
            acceleration_magnitude=acceleration_magnitude,
            classification=classification,
            timestamp=now,
        )

    def get_divergence_magnitude(self, divergence: np.ndarray) -> float:
        """L2 norm of the divergence vector."""
        return float(np.linalg.norm(divergence))

    def get_acceleration(self, dt: float = 1.0) -> np.ndarray:
        """Finite-difference acceleration from the last two recorded samples."""
        if len(self._divergence_history) < 2:
            return np.zeros(NUM_DIMENSIONS)

        delta = self._divergence_history[-1] - self._divergence_history[-2]
        if len(self._timestamp_history) >= 2:
            elapsed = self._timestamp_history[-1] - self._timestamp_history[-2]
            if elapsed > 1e-9:
                dt = elapsed
        return delta / max(dt, 1e-9)

    def classify(self, magnitude: float, accel_magnitude: float) -> DivergenceClassification:
        """Classify trajectory: NORMAL, RECOVERING, or ESCALATING."""
        if magnitude < 0.05:
            return DivergenceClassification.NORMAL
        elif accel_magnitude < 0:
            return DivergenceClassification.RECOVERING
        else:
            return DivergenceClassification.ESCALATING

    def reset(self) -> None:
        """Reset divergence history."""
        self._divergence_history.clear()
        self._timestamp_history.clear()
