"""
H¹¹ Genesis — Origin Attribution Operator (Ψ_c)
================================================

CCI and T_c answer a forward question: given damage here, where does it go?
Ψ_c answers the inverse. Given the divergence pattern D_c(t) that was actually
measured, which single dimension — perturbed alone and allowed to cascade
through T_c — best reproduces it?

The architecture already asserts how influence travels. Running that same
assertion backwards turns the coupling matrix into an attribution instrument
without introducing any new model of the system.
"""

from __future__ import annotations

import logging

import numpy as np

from h11_cga.types import (
    OriginHypothesis,
    NUM_DIMENSIONS,
    DIMENSION_NAMES,
)

logger = logging.getLogger(__name__)


class OriginTracer:
    """Attributes an observed divergence pattern to its most likely origin."""

    def __init__(
        self,
        coupling_matrix: np.ndarray,
        decay: float = 0.6,
        depth: int = 3,
    ) -> None:
        """
        Args:
            coupling_matrix: T_c, indexed [source, target].
            decay: Per-hop attenuation applied when building a signature.
            depth: How many cascade hops a signature reaches.
        """
        self._matrix = np.asarray(coupling_matrix, dtype=np.float64)
        self.decay = decay
        self.depth = max(0, int(depth))
        self._signatures: np.ndarray | None = None

    def set_matrix(self, coupling_matrix: np.ndarray) -> None:
        """Replace T_c and invalidate cached signatures."""
        self._matrix = np.asarray(coupling_matrix, dtype=np.float64)
        self._signatures = None

    def build_signatures(self) -> np.ndarray:
        """
        Expected error pattern for each candidate origin.

        Row i is what the state would look like if dimension i alone were hit:
            s_i = Σ_{h=0..depth} decay^h · (T_cᵀ)^h · u_i
        """
        if self._signatures is not None:
            return self._signatures

        signatures = np.zeros((NUM_DIMENSIONS, NUM_DIMENSIONS))
        transposed = self._matrix.T

        for i in range(NUM_DIMENSIONS):
            wave = np.zeros(NUM_DIMENSIONS)
            wave[i] = 1.0
            accumulated = np.zeros(NUM_DIMENSIONS)

            for hop in range(self.depth + 1):
                accumulated += (self.decay ** hop) * wave
                wave = transposed @ wave

            signatures[i] = accumulated

        self._signatures = signatures
        return signatures

    def trace(
        self,
        divergence_vector: np.ndarray,
        min_magnitude: float = 1e-6,
    ) -> list[OriginHypothesis]:
        """
        Rank candidate origins for an observed divergence.

        Args:
            divergence_vector: D_c(t) = X_c(t) - X_c*.
            min_magnitude: Below this norm the divergence is treated as noise.

        Returns:
            Hypotheses ordered by descending score. Empty when nothing diverged.
        """
        errors = np.abs(np.asarray(divergence_vector, dtype=np.float64))
        observed_norm = float(np.linalg.norm(errors))
        if observed_norm < min_magnitude:
            return []

        observed_unit = errors / observed_norm
        signatures = self.build_signatures()

        hypotheses: list[OriginHypothesis] = []
        for i in range(NUM_DIMENSIONS):
            sig_norm = float(np.linalg.norm(signatures[i]))
            if sig_norm < 1e-12:
                continue

            sig_unit = signatures[i] / sig_norm
            score = float(np.dot(sig_unit, observed_unit))

            # How much of the observed magnitude this signature accounts for.
            projection = score * observed_norm
            explained = float(np.clip(projection / observed_norm, 0.0, 1.0))

            hypotheses.append(
                OriginHypothesis(
                    dimension=i,
                    name=DIMENSION_NAMES[i],
                    score=score,
                    explained_fraction=explained,
                    observed_error=float(errors[i]),
                )
            )

        hypotheses.sort(key=lambda h: h.score, reverse=True)
        return hypotheses

    def most_likely_origin(
        self, divergence_vector: np.ndarray
    ) -> OriginHypothesis | None:
        """Return the single best-scoring origin, or None if nothing diverged."""
        ranked = self.trace(divergence_vector)
        return ranked[0] if ranked else None
