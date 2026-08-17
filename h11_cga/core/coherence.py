"""
H¹¹ Genesis — Cascade Coherence Auditor (Λ_c)
==============================================

Every tick, T_c makes an implicit claim: given the current residual, this is
where the state will move next. The architecture never checked that claim.

Λ_c records the prediction and grades it on the following tick. High coherence
means the coupling model explains the system's motion. Low coherence means the
state is moving for reasons T_c does not encode — which is itself a signal,
independent of whether divergence is large, because it marks behaviour the
architecture cannot currently account for.

The residual also says *where* the model was wrong, which is enough to correct
the coupling that produced it.
"""

from __future__ import annotations

import logging

import numpy as np

from h11_cga.types import CGAConfig, NUM_DIMENSIONS

logger = logging.getLogger(__name__)


class CoherenceAuditor:
    """Grades T_c against what the state actually did."""

    def __init__(self, config: CGAConfig) -> None:
        self.config = config
        self._predicted: np.ndarray | None = None
        self._previous_actual: np.ndarray | None = None
        self._last_residual: np.ndarray | None = None
        self._coherence_history: list[float] = []

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def record_prediction(
        self,
        current_vector: np.ndarray,
        cascade_delta: np.ndarray,
        residual: np.ndarray,
    ) -> np.ndarray:
        """
        Store where T_c says the state is heading.

        Args:
            current_vector: X_c(t).
            cascade_delta: The increment T_c produces this tick.
            residual: The divergence that drove that increment.

        Returns:
            The predicted X_c(t+1).
        """
        predicted = np.clip(current_vector + cascade_delta, 0.0, 1.0)
        self._predicted = predicted
        self._previous_actual = np.asarray(current_vector, dtype=np.float64).copy()
        self._last_residual = np.asarray(residual, dtype=np.float64).copy()
        return predicted

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def audit(self, actual_vector: np.ndarray) -> tuple[float, np.ndarray]:
        """
        Grade the previous prediction against what actually happened.

        Returns:
            (coherence, unexplained) where coherence ∈ [0, 1] and unexplained
            is the per-dimension signed miss. On the first tick, before any
            prediction exists, returns (1.0, zeros) — nothing has been claimed
            yet, so nothing can be wrong.
        """
        actual = np.asarray(actual_vector, dtype=np.float64)

        if self._predicted is None or self._previous_actual is None:
            return 1.0, np.zeros(NUM_DIMENSIONS)

        unexplained = actual - self._predicted
        error = float(np.linalg.norm(unexplained))
        motion = float(np.linalg.norm(actual - self._previous_actual))

        # A perfect prediction scores 1.0 whether or not the state moved.
        # Otherwise the miss is scored against the total motion it tried to
        # explain, which keeps the result in [0, 1] without a magic constant.
        if error < 1e-12:
            coherence = 1.0
        else:
            coherence = 1.0 - (error / (motion + error))

        coherence = float(np.clip(coherence, 0.0, 1.0))
        self._coherence_history.append(coherence)

        window = getattr(self.config, "dsa_history_window", 20)
        if len(self._coherence_history) > window:
            self._coherence_history = self._coherence_history[-window:]

        return coherence, unexplained

    # ------------------------------------------------------------------
    # Correction
    # ------------------------------------------------------------------

    def suggest_coupling_correction(
        self, unexplained: np.ndarray, rate: float
    ) -> np.ndarray:
        """
        Propose a T_c adjustment from the miss the audit just measured.

        The cascade claim is arrival_j = Σ_i T_c[i, j] · r_i. Reducing the
        squared error of that claim gives

            ΔT_c[i, j] = rate · r_i · unexplained_j

        which has the right sign on its own: a degraded source (r_i < 0) that
        delivered more damage than predicted (unexplained_j < 0) strengthens
        i→j, while an overstated edge weakens.

        Returns a zero matrix when there is nothing to learn from.
        """
        if rate <= 0.0 or self._last_residual is None:
            return np.zeros((NUM_DIMENSIONS, NUM_DIMENSIONS))

        if float(np.linalg.norm(self._last_residual)) < 1e-12:
            return np.zeros((NUM_DIMENSIONS, NUM_DIMENSIONS))

        if float(np.linalg.norm(unexplained)) < 1e-12:
            return np.zeros((NUM_DIMENSIONS, NUM_DIMENSIONS))

        correction = rate * np.outer(self._last_residual, unexplained)
        np.fill_diagonal(correction, 0.0)
        return correction

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def mean_coherence(self) -> float:
        """Average coherence over the retained window."""
        if not self._coherence_history:
            return 1.0
        return float(np.mean(self._coherence_history))

    def reset(self) -> None:
        """Clear predictions and history."""
        self._predicted = None
        self._previous_actual = None
        self._last_residual = None
        self._coherence_history.clear()
