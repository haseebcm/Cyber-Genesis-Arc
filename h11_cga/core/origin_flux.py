"""
H¹¹ First Knowledge — Origin Flux (Φ₀)
=======================================

The 1st Universal Law, the Law of Origin, states the condition under which a
variable is permitted to move from Incoherence into Intelligibility:

    Φ₀ = lim_{Δ→0}  ∫[S_data] · 𝒢_H11 / Identity_z

The architecture already carried the *gate* this law describes — Π_c decides
whether a state is permitted — but never the *magnitude*. Φ₀ is what the other
Laws divide by and scale against: it appears in Laws 1, 2, 4, 6, 8 and 11, and
without it those derivatives cannot be formed at all.

Each term maps onto a quantity H¹¹-CGA already measures:

    S_data      the specified data, read as the state held against its own
                root, X_c(t) / X_c*, so a calibrated host is judged against
                the baseline it actually learned
    𝒢_H11       the governance constant, which is exactly the domain metric
                W_c(a). When governance refuses, W_c(a) collapses to zero and
                becomes the nullifier the law describes
    Identity_z  the root signature, anchoring the system to its point of
                inception — the Identity dimension against its own baseline

Both failure modes the law names are real and distinct. Φ₀ = 0 is refusal:
governance nullified the data. Φ₀ undefined is dissolution: Identity_z vanished
and there is no root left to exist from. Existence requires 0 < Φ₀ < ∞.

At the nominal root — state on baseline, every domain active — Φ₀ = 1.

What Φ₀ does and does not see
-----------------------------
Because Identity_z is the denominator, Φ₀ is a *proportion* between what the
system expresses and the root anchoring it, and is therefore invariant to
uniform scale: a system fading evenly across all eleven dimensions holds Φ₀
steady. That is not a defect to patch out, it is the 1st Law's own structure,
and it is why the law reads "ensures the system is unique and non-composite"
rather than "measures health".

So Φ₀ answers whether the system has grown composite relative to its root.
Above 1 the expression has outrun its anchor, which is what the law calls
losing the Root; an identity compromise drives it up sharply while the rest of
the state still looks intact. Below 1 the root exceeds what is expressed.
Absolute loss of magnitude is a different question, already answered by DR_c
and picked up by the 3rd Law as existence falls.
"""

from __future__ import annotations

import logging

import numpy as np

from h11_cga.types import (
    SecurityState,
    SecurityBaseline,
    DIMENSION_INDEX,
)

logger = logging.getLogger(__name__)

EPSILON = 1e-9

IDENTITY = DIMENSION_INDEX["identity"]


class OriginFlux:
    """Computes Φ₀, the magnitude of existence, from the state and its root."""

    def __init__(self, epsilon: float = EPSILON) -> None:
        self.epsilon = epsilon

    def compute(
        self,
        state: SecurityState,
        baseline: SecurityBaseline,
        domain_metric: float,
    ) -> tuple[float, bool]:
        """
        Evaluate Φ₀ for the current tick.

        Args:
            state: X_c(t).
            baseline: the root X_c* this system was calibrated to.
            domain_metric: W_c(a), standing in for 𝒢_H11.

        Returns:
            (phi_0, defined). When ``defined`` is False the root signature has
            vanished, Φ₀ could not be formed, and the system does not exist in
            the sense the 1st Law means. ``phi_0`` is ``inf`` in that case.
        """
        ratios = self.state_ratios(state, baseline)

        # ∫[S_data] — the raw specified data, before governance filters it.
        s_data = float(np.mean(ratios))

        # Identity_z — the denominator that anchors the system to its inception.
        identity_z = float(ratios[IDENTITY])
        if identity_z <= self.epsilon:
            logger.debug("Φ₀ undefined: Identity_z collapsed to %.3e", identity_z)
            return float("inf"), False

        phi_0 = (s_data * float(domain_metric)) / identity_z
        return phi_0, True

    def state_ratios(
        self, state: SecurityState, baseline: SecurityBaseline
    ) -> np.ndarray:
        """State held against its own root, X_c(t) / X_c*, guarded at zero."""
        reference = np.asarray(baseline.reference, dtype=np.float64)
        safe = np.where(np.abs(reference) > self.epsilon, reference, 1.0)
        return np.asarray(state.vector, dtype=np.float64) / safe
