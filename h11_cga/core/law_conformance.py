"""
H¹¹ First Knowledge — The 11 Universal Laws (Λ₁₁)
==================================================

Every Universal Law in the framework carries a derivative condition and a value
that condition must hold. That is what makes the framework testable rather than
descriptive, and it is the part H¹¹-CGA had never implemented:

     1  Origin       dℰ/dO = 1              >1 Escalation, <1 Decay, =1 Stasis
     2  Creation     d²ℰ/dO² = 0            non-zero is acceleration away from
                                            the blueprint
     3  Existence    dEx/dt = 0             negative is dying, positive is
                                            growing out of control
     4  Boundary     dΣ/dV finite           an infinity is a failed calculation
     5  Constraint   dΩ/dt ≈ 0              at optimal constraint, work capacity
                                            is steady
     6  Limit        lim_{ℰ→L} dℰ/dt = 0    at the ceiling, change must stop
     7  Relation     dS₁/dℛ → 0             interaction must not destroy either
                                            participant's origin
     8  Action       dEnergy/d𝒜 minimal     true action is effortless when
                     at alignment           aligned with the grain
     9  Balance      d²ℬ/dt² → 0            a sovereign system returns to centre
    10  Evolution    dOrigin/dEvolution = 1 the signature must survive the change
    11  Resolution   ℛ_s → 1                ratio 1 resolves cleanly, otherwise
                                            it resolves violently

These are system-wide invariants evaluated over the whole 11-dimensional state,
not labels bound to individual dimensions. Only Law 1 names a dimension, taking
Identity as the root signature in its denominator.

Each Law is scored by how far its measured derivative sits from the value it
requires, giving conformance = 1/(1 + violation) in (0, 1]. Since the Laws
demand exact values and real telemetry never lands exactly, a tolerance band
decides what counts as Stasis.

Closing the arc, the H¹¹ Golden Ratio is not a decimal but a proportion between
the end and the beginning:

    Φ_H11 = Law₁₁ (Resolution) / Law₁ (Origin) → 1

which reads 1 when the system resolves exactly as well as it originated — a
loop with no waste.
"""

from __future__ import annotations

import logging
from collections import deque

import numpy as np

from h11_cga.types import (
    CGAConfig,
    LawConformance,
    LawConformanceReport,
    LawVerdict,
    ResponseAction,
    ActionUrgency,
    LAW_NAMES,
    NUM_DIMENSIONS,
)

logger = logging.getLogger(__name__)

EPSILON = 1e-12

URGENCY_WEIGHT: dict[ActionUrgency, float] = {
    ActionUrgency.LOW: 0.08,
    ActionUrgency.MEDIUM: 0.18,
    ActionUrgency.HIGH: 0.40,
    ActionUrgency.CRITICAL: 0.60,
}
"""Effort each urgency commits, matching the closed loop's convergence step."""


class LawConformanceEngine:
    """Audits one tick against all 11 Universal Laws."""

    def __init__(self, config: CGAConfig) -> None:
        self.config = config
        # Laws 2 and 9 are second derivatives and need three samples.
        self._phi0: deque[float] = deque(maxlen=3)
        self._balance: deque[float] = deque(maxlen=3)
        # Laws 3, 5 and 6 are first derivatives and need two.
        self._ex: deque[float] = deque(maxlen=2)
        self._omega: deque[float] = deque(maxlen=2)
        # Law 4 differentiates the boundary against internal pressure.
        self._sigma: deque[float] = deque(maxlen=2)
        self._pressure: deque[float] = deque(maxlen=2)
        # Law 10's ∫(Φ₀ → Φ_n): the sum of every state back to the Origin.
        self._ev_sum: float = 0.0
        self._ev_count: int = 0

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        *,
        origin_flux: float,
        origin_defined: bool,
        signature: float,
        lineage_ratio: float,
        divergence_magnitude: float,
        dr_adjusted: float,
        limit_utilization: float,
        domain_metric: float,
        chaos: float,
        cascade_delta: np.ndarray,
        actions: list[ResponseAction],
        deficit: np.ndarray,
    ) -> LawConformanceReport:
        """
        Grade the system against every Law.

        Args:
            origin_flux: Φ₀ for this tick.
            origin_defined: False when Identity_z vanished.
            signature: S_ig for this tick.
            lineage_ratio: S_ig(t)/S_ig(t−1), the 10th Law's derivative.
            divergence_magnitude: ‖D_c‖, read as ℛ_friction in the 3rd Law.
            dr_adjusted: DR_c^(a), read as external pressure in the 4th Law.
            limit_utilization: Ω_s, proximity to the ceiling for the 6th Law.
            domain_metric: W_c(a), the governance constant 𝒢_H11.
            chaos: ‖unexplained‖ from Λ_c, read as Λ_chaos in the 5th Law.
            cascade_delta: this tick's T_c increment, the relational force.
            actions: ΔCR's recommendations, whose alignment the 8th Law scores.
            deficit: X_c* − X_c(t), what those actions ought to be aimed at.

        Returns:
            The full 11-Law report including Φ_H11.
        """
        if not origin_defined:
            # "If Φ₀ is zero or undefined, the system does not exist." No
            # derivative can be formed without a root to take it against.
            return self._dissolved_report(signature)

        # --- Derived quantities the Laws are written in terms of ---
        friction = 1.0 + max(0.0, divergence_magnitude)
        ex = origin_flux * signature / friction
        sigma = origin_flux * signature / (1.0 + max(0.0, dr_adjusted))
        omega = domain_metric / (1.0 + max(0.0, chaos))
        balance = float(np.sum(cascade_delta))
        relation = float(np.linalg.norm(cascade_delta))
        alignment = self._action_alignment(actions, deficit)

        # ℰ_v — the evolutionary path, accumulated from the Origin forward.
        self._ev_sum += origin_flux * signature
        self._ev_count += 1
        evolution = self._ev_sum / self._ev_count

        # ℛ_s = ∫(ℰ_v / Φ₀) — the verification ratio. Unity means the evolved
        # system still matches the root it came from.
        resolution = (
            evolution / origin_flux if origin_flux > EPSILON else float("inf")
        )

        self._phi0.append(origin_flux)
        self._ex.append(ex)
        self._omega.append(omega)
        self._balance.append(balance)
        self._sigma.append(sigma)
        self._pressure.append(limit_utilization)

        laws = [
            self._law(1, origin_flux, 1.0),
            self._law(2, self._second_difference(self._phi0), 0.0),
            self._law(3, self._first_difference(self._ex), 0.0),
            self._law_boundary(),
            self._law(5, self._first_difference(self._omega), 0.0),
            self._law(6, abs(self._first_difference(self._ex)) * limit_utilization, 0.0),
            self._law(7, relation, 0.0),
            self._law(8, alignment, 1.0),
            self._law(9, self._second_difference(self._balance), 0.0),
            self._law(10, lineage_ratio, 1.0),
            self._law(11, resolution, 1.0),
        ]

        return LawConformanceReport(
            laws=laws,
            phi_h11=self._golden_ratio(resolution, origin_flux),
            origin_flux=origin_flux,
            origin_defined=True,
            sovereign_signature=signature,
        )

    # ------------------------------------------------------------------
    # Individual laws
    # ------------------------------------------------------------------

    def _law(
        self,
        number: int,
        measured: float,
        required: float,
        *,
        violation: float | None = None,
        verdict: LawVerdict | None = None,
    ) -> LawConformance:
        """Score one Law against the value its derivative condition demands."""
        measured = float(measured)
        if violation is None:
            violation = abs(measured - required)

        if verdict is None:
            if violation <= self.config.law_violation_tolerance:
                verdict = LawVerdict.STASIS
            elif measured > required:
                verdict = LawVerdict.ESCALATION
            else:
                verdict = LawVerdict.DECAY

        return LawConformance(
            law=number,
            name=LAW_NAMES[number - 1],
            measured=measured,
            required=float(required),
            violation=float(violation),
            conformance=1.0 / (1.0 + violation),
            verdict=verdict,
        )

    def _law_boundary(self) -> LawConformance:
        """
        Law 4 — dΣ/dV must stay finite.

        Unlike the others this Law names no target value, only a quality: the
        edge must be sharp. A boundary whose response to internal pressure runs
        away has blurred, and in H¹¹ physics an infinity is the signature of a
        failed calculation rather than a large result.
        """
        bound = self.config.law_boundary_bound

        if len(self._sigma) < 2 or len(self._pressure) < 2:
            return self._law(4, 0.0, 0.0, violation=0.0, verdict=LawVerdict.STASIS)

        d_sigma = self._sigma[-1] - self._sigma[-2]
        d_volume = self._pressure[-1] - self._pressure[-2]

        if abs(d_volume) < EPSILON:
            # Pressure held steady. With no change to respond to, the boundary
            # cannot be shown to have blurred.
            measured = 0.0 if abs(d_sigma) < EPSILON else float("inf")
        else:
            measured = d_sigma / d_volume

        excess = max(0.0, abs(measured) - bound)
        verdict = LawVerdict.STASIS if excess <= 0.0 else LawVerdict.ESCALATION
        return self._law(4, measured, 0.0, violation=excess, verdict=verdict)

    def _action_alignment(
        self, actions: list[ResponseAction], deficit: np.ndarray
    ) -> float:
        """
        Law 8's cos(θ) — how squarely ΔCR's effort lands on the actual damage.

        The framework is explicit that action against the grain does no work:
        at θ = 0 efficiency is total, at θ = 90° the output is zero. Here the
        grain is the deficit X_c* − X_c(t), and the action vector is the effort
        ΔCR proposes per dimension.

        With no action proposed, or nothing to repair, there is no misaligned
        work to charge, so alignment reads 1.
        """
        effort = np.zeros(NUM_DIMENSIONS)
        for action in actions:
            if 0 <= action.dimension < NUM_DIMENSIONS:
                effort[action.dimension] += URGENCY_WEIGHT.get(action.urgency, 0.1)

        target = np.clip(np.asarray(deficit, dtype=np.float64), 0.0, None)

        norm_effort = float(np.linalg.norm(effort))
        norm_target = float(np.linalg.norm(target))
        if norm_effort < EPSILON or norm_target < EPSILON:
            return 1.0

        return float(
            np.clip(np.dot(effort, target) / (norm_effort * norm_target), 0.0, 1.0)
        )

    @staticmethod
    def _golden_ratio(resolution: float, origin_flux: float) -> float:
        """
        Φ_H11 = Law₁₁ (Resolution) / Law₁ (Origin) — End over Beginning.

        The framework rejects the Golden Ratio as a decimal and restates it as
        an axiom of alignment: perfect proportion is reached when the End
        matches the Beginning, closing the loop with zero waste.

        This is taken over the two Laws' measured values rather than their
        conformance scores. Scoring it on conformance looks tempting but is
        wrong: two Laws failing by the same amount would divide out to a
        flawless 1.0 on a system that had already dissolved.
        """
        if origin_flux < EPSILON:
            return float("inf")
        return resolution / origin_flux

    # ------------------------------------------------------------------
    # Derivatives
    # ------------------------------------------------------------------

    @staticmethod
    def _first_difference(history: deque[float]) -> float:
        """d/dt over one tick; zero until there are two samples."""
        if len(history) < 2:
            return 0.0
        return history[-1] - history[-2]

    @staticmethod
    def _second_difference(history: deque[float]) -> float:
        """d²/dt² over two ticks; zero until there are three samples."""
        if len(history) < 3:
            return 0.0
        return history[-1] - 2.0 * history[-2] + history[-3]

    # ------------------------------------------------------------------
    # Dissolution
    # ------------------------------------------------------------------

    def _dissolved_report(self, signature: float) -> LawConformanceReport:
        """Every Law reads Undefined once the root signature is gone."""
        laws = [
            LawConformance(
                law=n,
                name=LAW_NAMES[n - 1],
                measured=float("inf"),
                required=0.0,
                violation=float("inf"),
                conformance=0.0,
                verdict=LawVerdict.UNDEFINED,
            )
            for n in range(1, NUM_DIMENSIONS + 1)
        ]
        return LawConformanceReport(
            laws=laws,
            phi_h11=float("inf"),
            origin_flux=float("inf"),
            origin_defined=False,
            sovereign_signature=signature,
            mean_conformance=0.0,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Clear all derivative history."""
        self._phi0.clear()
        self._ex.clear()
        self._omega.clear()
        self._balance.clear()
        self._sigma.clear()
        self._pressure.clear()
        self._ev_sum = 0.0
        self._ev_count = 0
