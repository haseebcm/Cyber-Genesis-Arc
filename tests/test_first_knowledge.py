"""
H¹¹-CGA 4.0 First Knowledge Tests
==================================

Covers the layer that binds the architecture to its actual root: the Origin
Flux (Φ₀), the Sovereign Signature (S_ig), the 11 Universal Laws and their
derivative conditions, and the H¹¹ Golden Ratio Φ_H11 that closes the arc.
"""

import numpy as np
import pytest

from h11_cga import (
    CyberGenesisEngine,
    CGAConfig,
    SecurityState,
    SecurityBaseline,
    DomainVector,
    LawVerdict,
    OriginFlux,
    SovereignSignature,
    LawConformanceEngine,
    LAW_NAMES,
    NUM_DIMENSIONS,
    DIMENSION_INDEX,
)
from h11_cga.core.coherence import CoherenceAuditor

IDENTITY = DIMENSION_INDEX["identity"]


def _state(vector) -> SecurityState:
    return SecurityState(vector=np.asarray(vector, dtype=np.float64))


def _baseline(reference=None) -> SecurityBaseline:
    if reference is None:
        reference = np.ones(NUM_DIMENSIONS)
    return SecurityBaseline(reference=np.asarray(reference, dtype=np.float64))


def _law_kwargs(**overrides):
    """Neutral inputs for the conformance engine; override what a test exercises."""
    base = dict(
        origin_flux=1.0,
        origin_defined=True,
        signature=1.0,
        lineage_ratio=1.0,
        divergence_magnitude=0.0,
        dr_adjusted=0.0,
        limit_utilization=0.0,
        domain_metric=1.0,
        chaos=0.0,
        cascade_delta=np.zeros(NUM_DIMENSIONS),
        actions=[],
        deficit=np.zeros(NUM_DIMENSIONS),
    )
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Φ₀ — Origin Flux (Law 1)
# ---------------------------------------------------------------------------

def test_origin_flux_is_unity_at_the_nominal_root():
    """State on baseline with full governance is exactly one unit of existence."""
    phi_0, defined = OriginFlux().compute(
        _state(np.ones(NUM_DIMENSIONS)), _baseline(), domain_metric=1.0
    )
    assert defined
    assert phi_0 == pytest.approx(1.0)


def test_origin_flux_is_unity_against_a_calibrated_root():
    """A host that learned a baseline of 0.8 sits at its own origin, not at 1.0."""
    reference = np.full(NUM_DIMENSIONS, 0.8)
    phi_0, defined = OriginFlux().compute(
        _state(reference), _baseline(reference), domain_metric=1.0
    )
    assert defined
    assert phi_0 == pytest.approx(1.0)


def test_governance_nullification_collapses_origin_flux():
    """𝒢_H11 = 0 is the nullifier: no governance, no existence."""
    phi_0, defined = OriginFlux().compute(
        _state(np.ones(NUM_DIMENSIONS)), _baseline(), domain_metric=0.0
    )
    assert defined
    assert phi_0 == pytest.approx(0.0)


def test_origin_undefined_when_the_root_signature_vanishes():
    """Identity_z is the denominator; without it Φ₀ cannot be formed at all."""
    vector = np.ones(NUM_DIMENSIONS)
    vector[IDENTITY] = 0.0

    phi_0, defined = OriginFlux().compute(_state(vector), _baseline(), domain_metric=1.0)

    assert not defined
    assert phi_0 == float("inf")


def test_origin_flux_rises_when_data_outruns_its_identity_anchor():
    """Law 1's Escalation: the system carries more than its Root can anchor."""
    vector = np.ones(NUM_DIMENSIONS)
    vector[IDENTITY] = 0.5

    phi_0, defined = OriginFlux().compute(_state(vector), _baseline(), domain_metric=1.0)

    assert defined
    assert phi_0 > 1.0


def test_origin_flux_is_invariant_to_uniform_scale():
    """Φ₀ is a proportion of expression to anchor, so even decay cancels out.

    This is intrinsic to the 1st Law: Identity_z is the denominator. A system
    that fades uniformly keeps its Origin intact and is caught elsewhere — by
    DR_c on magnitude, and by Law 3 as existence falls. What Φ₀ detects is the
    system becoming composite relative to its root.
    """
    flux = OriginFlux()
    at_root, _ = flux.compute(
        _state(np.ones(NUM_DIMENSIONS)), _baseline(), domain_metric=1.0
    )
    faded, _ = flux.compute(
        _state(np.full(NUM_DIMENSIONS, 0.4)), _baseline(), domain_metric=1.0
    )

    assert faded == pytest.approx(at_root)


# ---------------------------------------------------------------------------
# S_ig — Sovereign Signature
# ---------------------------------------------------------------------------

def test_signature_is_unity_at_the_root():
    assert SovereignSignature().compute(
        _state(np.ones(NUM_DIMENSIONS)), _baseline()
    ) == pytest.approx(1.0)


def test_uniform_decay_preserves_the_signature():
    """Losing magnitude evenly is decay; the system still has its own form."""
    signature = SovereignSignature().compute(
        _state(np.full(NUM_DIMENSIONS, 0.4)), _baseline()
    )
    assert signature == pytest.approx(1.0)


def test_uneven_degradation_breaks_the_signature():
    """Losing one dimension changes the shape, which is what S_ig measures."""
    vector = np.ones(NUM_DIMENSIONS)
    vector[DIMENSION_INDEX["data"]] = 0.0

    signature = SovereignSignature().compute(_state(vector), _baseline())

    assert signature < 1.0


def test_signature_separates_decay_from_mutation():
    """Uniform loss and targeted loss differ in form even at equal magnitude."""
    uniform = np.full(NUM_DIMENSIONS, 10.0 / NUM_DIMENSIONS)
    targeted = np.ones(NUM_DIMENSIONS)
    targeted[DIMENSION_INDEX["data"]] = 0.0
    assert np.sum(uniform) == pytest.approx(np.sum(targeted))

    sig_uniform = SovereignSignature().compute(_state(uniform), _baseline())
    sig_targeted = SovereignSignature().compute(_state(targeted), _baseline())

    assert sig_uniform > sig_targeted


def test_signature_is_not_cascade_coherence():
    """S_ig and Λ_c answer different questions and must be able to disagree.

    A collapse that T_c predicted perfectly scores high coherence while the
    system stops resembling itself. 3.0 could only see the first half.
    """
    config = CGAConfig()
    auditor = CoherenceAuditor(config)
    baseline = _baseline()

    collapsing = np.ones(NUM_DIMENSIONS)
    collapsing[DIMENSION_INDEX["data"]] = 0.1

    # T_c called the move exactly: nothing about it is unexplained.
    auditor.record_prediction(
        np.ones(NUM_DIMENSIONS),
        collapsing - np.ones(NUM_DIMENSIONS),
        np.zeros(NUM_DIMENSIONS),
    )
    coherence, _ = auditor.audit(collapsing)
    signature = SovereignSignature().compute(_state(collapsing), baseline)

    assert coherence == pytest.approx(1.0)
    assert signature < 0.99


def test_lineage_ratio_is_unity_before_anything_has_evolved():
    sig = SovereignSignature()
    sig.compute(_state(np.ones(NUM_DIMENSIONS)), _baseline())
    assert sig.lineage_ratio() == pytest.approx(1.0)
    assert sig.drift == pytest.approx(0.0)


def test_lineage_ratio_falls_when_the_signature_is_lost():
    sig = SovereignSignature()
    baseline = _baseline()
    sig.compute(_state(np.ones(NUM_DIMENSIONS)), baseline)

    mutated = np.ones(NUM_DIMENSIONS)
    mutated[DIMENSION_INDEX["trust"]] = 0.0
    sig.compute(_state(mutated), baseline)

    assert sig.lineage_ratio() < 1.0
    assert sig.drift > 0.0


# ---------------------------------------------------------------------------
# The 11 Laws
# ---------------------------------------------------------------------------

def test_every_law_conforms_at_rest():
    report = LawConformanceEngine(CGAConfig()).evaluate(**_law_kwargs())

    assert len(report.laws) == 11
    assert [law.name for law in report.laws] == list(LAW_NAMES)
    assert report.sovereign
    assert report.violated == []
    assert report.mean_conformance == pytest.approx(1.0)


def test_law1_reads_decay_below_unity_and_escalation_above():
    engine = LawConformanceEngine(CGAConfig())
    decaying = engine.evaluate(**_law_kwargs(origin_flux=0.5)).laws[0]

    engine.reset()
    escalating = engine.evaluate(**_law_kwargs(origin_flux=1.8)).laws[0]

    assert decaying.verdict is LawVerdict.DECAY
    assert escalating.verdict is LawVerdict.ESCALATION


def test_law2_flags_acceleration_away_from_the_blueprint():
    """d²ℰ/dO² must be zero; steady drift is legal, acceleration is not."""
    engine = LawConformanceEngine(CGAConfig())
    for phi in (1.0, 0.9, 0.8):
        linear = engine.evaluate(**_law_kwargs(origin_flux=phi)).laws[1]
    assert linear.verdict is LawVerdict.STASIS

    engine.reset()
    for phi in (1.0, 0.9, 0.5):
        accelerating = engine.evaluate(**_law_kwargs(origin_flux=phi)).laws[1]
    assert accelerating.verdict is not LawVerdict.STASIS


def test_law3_reads_decay_when_existence_falls():
    engine = LawConformanceEngine(CGAConfig())
    engine.evaluate(**_law_kwargs(origin_flux=1.0))
    dying = engine.evaluate(**_law_kwargs(origin_flux=0.4)).laws[2]

    assert dying.verdict is LawVerdict.DECAY


def test_law6_only_penalises_change_near_the_ceiling():
    """The Limit forbids motion at the ceiling, not motion in open space."""
    far = LawConformanceEngine(CGAConfig())
    far.evaluate(**_law_kwargs(origin_flux=1.0, limit_utilization=0.0))
    open_space = far.evaluate(**_law_kwargs(origin_flux=0.5, limit_utilization=0.0))

    near = LawConformanceEngine(CGAConfig())
    near.evaluate(**_law_kwargs(origin_flux=1.0, limit_utilization=1.0))
    at_ceiling = near.evaluate(**_law_kwargs(origin_flux=0.5, limit_utilization=1.0))

    assert open_space.laws[5].verdict is LawVerdict.STASIS
    assert at_ceiling.laws[5].verdict is LawVerdict.ESCALATION


def test_law7_flags_relation_that_erodes_its_participants():
    engine = LawConformanceEngine(CGAConfig())
    eroding = np.zeros(NUM_DIMENSIONS)
    eroding[DIMENSION_INDEX["memory"]] = -0.8

    report = engine.evaluate(**_law_kwargs(cascade_delta=eroding))

    assert report.laws[6].verdict is not LawVerdict.STASIS


def test_law8_scores_action_aimed_at_the_actual_damage():
    """cos(θ) = 1 when ΔCR's effort lands on the deficit, 0 when it misses."""
    from h11_cga import ResponseAction, ActionUrgency

    deficit = np.zeros(NUM_DIMENSIONS)
    deficit[DIMENSION_INDEX["data"]] = 0.6

    aimed = [ResponseAction(dimension=DIMENSION_INDEX["data"], urgency=ActionUrgency.HIGH)]
    astray = [ResponseAction(dimension=DIMENSION_INDEX["trust"], urgency=ActionUrgency.HIGH)]

    on_grain = LawConformanceEngine(CGAConfig()).evaluate(
        **_law_kwargs(actions=aimed, deficit=deficit)
    ).laws[7]
    off_grain = LawConformanceEngine(CGAConfig()).evaluate(
        **_law_kwargs(actions=astray, deficit=deficit)
    ).laws[7]

    assert on_grain.measured == pytest.approx(1.0)
    assert on_grain.verdict is LawVerdict.STASIS
    assert off_grain.measured == pytest.approx(0.0)
    assert off_grain.verdict is LawVerdict.DECAY


def test_law8_charges_nothing_when_no_action_was_proposed():
    """No action taken is not misaligned action; the Law scores work done."""
    deficit = np.zeros(NUM_DIMENSIONS)
    deficit[DIMENSION_INDEX["data"]] = 0.6

    law = LawConformanceEngine(CGAConfig()).evaluate(
        **_law_kwargs(actions=[], deficit=deficit)
    ).laws[7]

    assert law.verdict is LawVerdict.STASIS


def test_law10_flags_mutation_when_the_signature_is_not_preserved():
    engine = LawConformanceEngine(CGAConfig())
    report = engine.evaluate(**_law_kwargs(lineage_ratio=0.6))

    assert report.laws[9].verdict is LawVerdict.DECAY


def test_law4_tolerates_a_finite_edge_and_flags_a_blurred_one():
    """Law 4 names no target, only that the edge must stay finite."""
    steady = LawConformanceEngine(CGAConfig())
    steady.evaluate(**_law_kwargs(limit_utilization=0.10))
    finite = steady.evaluate(**_law_kwargs(limit_utilization=0.20, dr_adjusted=0.05))
    assert finite.laws[3].verdict is LawVerdict.STASIS

    config = CGAConfig(law_boundary_bound=0.001)
    blurred = LawConformanceEngine(config)
    blurred.evaluate(**_law_kwargs(limit_utilization=0.10))
    runaway = blurred.evaluate(**_law_kwargs(limit_utilization=0.1000001, dr_adjusted=0.9))
    assert runaway.laws[3].verdict is LawVerdict.ESCALATION


def test_dissolution_marks_every_law_undefined():
    """With no root, no derivative can be taken against it."""
    report = LawConformanceEngine(CGAConfig()).evaluate(
        **_law_kwargs(origin_flux=float("inf"), origin_defined=False)
    )

    assert not report.origin_defined
    assert not report.sovereign
    assert len(report.laws) == 11
    assert all(law.verdict is LawVerdict.UNDEFINED for law in report.laws)
    assert report.mean_conformance == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# Φ_H11 — closing the arc
# ---------------------------------------------------------------------------

def test_golden_ratio_is_unity_at_the_root():
    report = LawConformanceEngine(CGAConfig()).evaluate(**_law_kwargs())
    assert report.phi_h11 == pytest.approx(1.0)


def test_golden_ratio_does_not_read_closed_on_a_dissolved_system():
    """Regression: scoring Φ_H11 on conformance let two equal failures cancel.

    Law 1 and Law 11 both missing by the same amount divided out to a flawless
    1.0 on a system that had already stopped existing.
    """
    engine = LawConformanceEngine(CGAConfig())
    engine.evaluate(**_law_kwargs())
    collapsed = engine.evaluate(**_law_kwargs(origin_flux=0.0))

    assert not collapsed.sovereign
    assert collapsed.phi_h11 != pytest.approx(1.0)
    assert collapsed.phi_h11 == float("inf")


def test_golden_ratio_opens_when_resolution_outruns_origin():
    engine = LawConformanceEngine(CGAConfig())
    engine.evaluate(**_law_kwargs())
    engine.evaluate(**_law_kwargs())
    degraded = engine.evaluate(**_law_kwargs(origin_flux=0.5))

    assert degraded.phi_h11 > 1.0


# ---------------------------------------------------------------------------
# Authority — advisory by default
# ---------------------------------------------------------------------------

def test_law_layer_is_advisory_by_default():
    """A broken Law reports, but does not touch Π_c, unless asked to.

    Identity compromise at this severity breaks Law 1 — data outrunning its
    anchor — while Π_c on its own is still satisfied, which is exactly the
    gap the authoritative switch decides what to do about.
    """
    engine = CyberGenesisEngine()
    assessment = engine.inject_attack("identity_compromise", severity=0.2)

    assert assessment.law_conformance is not None
    assert 1 in [law.law for law in assessment.law_conformance.violated]
    assert assessment.permission == 1.0
    assert assessment.status.value != "EMERGENCY"


def test_authoritative_mode_revokes_permission_on_a_broken_law():
    """𝒢_H11 nullifies when the data does not comply, and existence is refused."""
    engine = CyberGenesisEngine(CGAConfig(law_authoritative=True))
    assessment = engine.inject_attack("identity_compromise", severity=0.2)

    assert not assessment.law_conformance.sovereign
    assert assessment.permission == 0.0
    assert assessment.status.value == "EMERGENCY"


def test_authoritative_mode_leaves_a_conformant_system_alone():
    engine = CyberGenesisEngine(CGAConfig(law_authoritative=True))
    assessment = engine.process_tick()

    assert assessment.law_conformance.sovereign
    assert assessment.permission == 1.0


def test_law_layer_can_be_disabled_entirely():
    engine = CyberGenesisEngine(CGAConfig(law_conformance_enabled=False))
    assessment = engine.process_tick()

    assert assessment.law_conformance is None
    # Φ₀ and S_ig are cheap and always measured; only the audit is optional.
    assert assessment.origin_flux == pytest.approx(1.0)
    assert assessment.sovereign_signature == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------

def test_assessment_and_dashboard_carry_first_knowledge():
    engine = CyberGenesisEngine()
    engine.process_tick()
    dashboard = engine.get_dashboard()

    assert dashboard["origin_flux"] == pytest.approx(1.0)
    assert dashboard["sovereign_signature"] == pytest.approx(1.0)
    assert dashboard["law_conformance"]["sovereign"] is True
    assert len(dashboard["law_conformance"]["laws"]) == 11

    summary = engine.get_assessment_history()[-1].summary()
    assert summary["phi_h11"] == pytest.approx(1.0)
    assert summary["laws_violated"] == []


def test_reset_clears_law_derivative_history():
    engine = CyberGenesisEngine()
    engine.inject_attack("ddos", severity=0.7)
    engine.reset()

    assessment = engine.process_tick()

    assert assessment.origin_flux == pytest.approx(1.0)
    assert assessment.sovereign_signature == pytest.approx(1.0)
    assert assessment.law_conformance.sovereign
    assert assessment.law_conformance.phi_h11 == pytest.approx(1.0)


def test_nominal_operation_stays_sovereign_across_many_ticks():
    engine = CyberGenesisEngine()
    for _ in range(20):
        assessment = engine.process_tick()

    assert assessment.law_conformance.sovereign
    assert assessment.origin_flux == pytest.approx(1.0)
