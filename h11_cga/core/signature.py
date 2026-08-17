"""
H¹¹ First Knowledge — Sovereign Signature (S_ig)
=================================================

S_ig is the most load-bearing quantity in the framework after Φ₀: the 3rd Law
powers Existence with it, the 4th Law sets boundary permeability by it, the 8th
Law scales Action through it, the 9th Law balances modulo it, and the 10th Law
requires it to survive change or the change is Mutation rather than Evolution.

The framework defines it as the Coherence Factor: how closely the system still
reflects its Originator. If the system loses its signature — its connection to
the Root — the value drops and existence ceases.

This is *not* what Λ_c measures. Λ_c, added in 3.0, grades whether T_c predicted
the state's motion; it is an audit of the model. S_ig asks something the
architecture had no way to answer: whether the system still has the shape of the
thing it was calibrated to be.

The two are deliberately independent. A perfectly predictable collapse scores
high on Λ_c and low on S_ig — the model understood exactly what was happening
while the system stopped resembling itself.

S_ig is measured as the alignment between X_c(t) and its root X_c*, which
captures form rather than magnitude. A system degrading uniformly keeps its
signature and loses Φ₀; a system degrading unevenly loses its signature. That
split is what lets the Laws distinguish decay from mutation.
"""

from __future__ import annotations

import logging

import numpy as np

from h11_cga.types import SecurityState, SecurityBaseline

logger = logging.getLogger(__name__)

EPSILON = 1e-12


class SovereignSignature:
    """Measures S_ig and the drift the 10th Law forbids."""

    def __init__(self) -> None:
        self._current: float = 1.0
        self._previous: float | None = None

    def compute(self, state: SecurityState, baseline: SecurityBaseline) -> float:
        """
        Evaluate S_ig for this tick and retain it for the lineage check.

        Returns the alignment of X_c(t) with X_c* in [0, 1], where 1 means the
        system still holds exactly the form of its root.
        """
        x = np.asarray(state.vector, dtype=np.float64)
        root = np.asarray(baseline.reference, dtype=np.float64)

        norm_x = float(np.linalg.norm(x))
        norm_root = float(np.linalg.norm(root))

        if norm_x < EPSILON or norm_root < EPSILON:
            # Nothing left to compare, or no root to compare against.
            signature = 0.0
        else:
            signature = float(np.clip(np.dot(x, root) / (norm_x * norm_root), 0.0, 1.0))

        self._previous = self._current
        self._current = signature
        return signature

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def current(self) -> float:
        """S_ig as of the most recent evaluation."""
        return self._current

    @property
    def previous(self) -> float | None:
        """S_ig from the prior tick; None before a second evaluation."""
        return self._previous

    @property
    def drift(self) -> float:
        """|dS_ig/dt| — how much the signature moved. Zero before two ticks."""
        if self._previous is None:
            return 0.0
        return abs(self._current - self._previous)

    def lineage_ratio(self) -> float:
        """
        S_ig(t) / S_ig(t−1) — the 10th Law's dOrigin/dEvolution.

        Unity means the signature survived whatever change occurred, which is
        the framework's test for legal evolution. Returns 1.0 before there is a
        prior signature to compare against, since nothing has evolved yet.
        """
        if self._previous is None or self._previous < EPSILON:
            return 1.0
        return self._current / self._previous

    def reset(self) -> None:
        """Clear the retained signature history."""
        self._current = 1.0
        self._previous = None
