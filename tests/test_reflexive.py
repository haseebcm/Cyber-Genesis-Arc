"""
H¹¹-CGA 3.0 Reflexive Operator Tests
=====================================

Covers the operators that turn the architecture back on itself: origin
attribution (Ψ_c), cascade coherence (Λ_c), scope cost (K_c), and permission
debt — plus the T_c orientation they all depend on.
"""

import numpy as np
import pytest

from h11_cga import (
    CyberGenesisEngine,
    CGAConfig,
    SecurityState,
    SecurityBaseline,
    DomainVector,
    TelemetryInput,
    TransformationMatrix,
    OriginTracer,
    CoherenceAuditor,
    NUM_DIMENSIONS,
    DIMENSION_INDEX,
)
from h11_cga.core.cci import CascadeAnalyzer
from h11_cga.core.genesis import GenesisPermission
from h11_cga.core.domain_nullification import DomainNullifier


# ---------------------------------------------------------------------------
# T_c orientation — everything reflexive depends on this being right
# ---------------------------------------------------------------------------

def test_cascade_flows_from_source_to_target():
    """T_c[i, j] is influence i→j, so perturbing i must land on j."""
    tc = TransformationMatrix()
    identity = DIMENSION_INDEX["identity"]
    authorization = DIMENSION_INDEX["authorization"]

    assert tc.get_influence("identity", "authorization") == pytest.approx(0.85)

    perturbation = np.zeros(NUM_DIMENSIONS)
    perturbation[identity] = 1.0
    delta = tc.propagate_delta(perturbation, dt=1.0)

    assert delta[authorization] == pytest.approx(0.85)
    assert delta[identity] == pytest.approx(0.0)


def test_cci_couples_along_declared_direction():
    """Error on a source must raise CCI through that source's outgoing edges."""
    config = CGAConfig()
    matrix = np.zeros((NUM_DIMENSIONS, NUM_DIMENSIONS))
    src, dst = 0, 5
    matrix[src, dst] = 0.9

    analyzer = CascadeAnalyzer(config, coupling_matrix=matrix)

    errors_at_source = np.zeros(NUM_DIMENSIONS)
    errors_at_source[src] = 1.0

    errors_at_target = np.zeros(NUM_DIMENSIONS)
    errors_at_target[dst] = 1.0

    # Linear terms are equal, so any difference is the coupling term.
    assert analyzer.compute_cci(errors_at_source) > analyzer.compute_cci(errors_at_target)


def test_cascade_gated_by_domain_activation():
    tc = TransformationMatrix()
    perturbation = np.ones(NUM_DIMENSIONS)

    dv = DomainVector()
    dv.nullify("authorization")

    delta = tc.propagate_delta(perturbation, dt=1.0, domain_vector=dv)
    assert delta[DIMENSION_INDEX["authorization"]] == pytest.approx(0.0)
    assert np.any(delta > 0)


# ---------------------------------------------------------------------------
# Ψ_c — origin attribution
# ---------------------------------------------------------------------------

def test_origin_tracer_recovers_injected_origin():
    engine = CyberGenesisEngine()
    engine.process_tick()
    assessment = engine.inject_attack("identity_compromise", severity=0.6)

    assert assessment.origin_hypotheses
    assert assessment.origin_hypotheses[0].name == "Identity"
    assert assessment.origin_hypotheses[0].score > 0.5


def test_origin_tracer_distinguishes_attacks():
    engine = CyberGenesisEngine()
    engine.process_tick()
    ransomware = engine.inject_attack("ransomware", severity=0.6)

    # Ransomware's heaviest hit is data; identity is untouched by the pattern.
    assert ransomware.origin_hypotheses[0].name == "Data"
    names = [h.name for h in ransomware.origin_hypotheses]
    assert "Identity" not in names


def test_origin_tracer_silent_when_nothing_diverged():
    tracer = OriginTracer(TransformationMatrix().as_array())
    assert tracer.trace(np.zeros(NUM_DIMENSIONS)) == []
    assert tracer.most_likely_origin(np.zeros(NUM_DIMENSIONS)) is None


def test_origin_signature_follows_coupling_not_symmetry():
    """identity→trust exists; recovery→trust is weaker, so signatures differ."""
    tracer = OriginTracer(TransformationMatrix().as_array(), decay=0.6, depth=2)
    signatures = tracer.build_signatures()

    trust = DIMENSION_INDEX["trust"]
    identity = DIMENSION_INDEX["identity"]
    network = DIMENSION_INDEX["network"]

    assert signatures[identity][trust] > signatures[network][trust]


def test_origin_hypotheses_ranked_descending():
    engine = CyberGenesisEngine()
    engine.process_tick()
    assessment = engine.inject_attack("zero_day", severity=0.5)

    scores = [h.score for h in assessment.origin_hypotheses]
    assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# Λ_c — cascade coherence
# ---------------------------------------------------------------------------

def test_coherence_perfect_before_any_prediction():
    auditor = CoherenceAuditor(CGAConfig())
    coherence, unexplained = auditor.audit(np.ones(NUM_DIMENSIONS))
    assert coherence == 1.0
    assert not np.any(unexplained)


def test_coherence_perfect_when_prediction_holds():
    auditor = CoherenceAuditor(CGAConfig())
    current = np.full(NUM_DIMENSIONS, 0.8)
    delta = np.full(NUM_DIMENSIONS, 0.05)

    predicted = auditor.record_prediction(current, delta, current - 1.0)
    coherence, unexplained = auditor.audit(predicted)

    assert coherence == pytest.approx(1.0)
    assert np.allclose(unexplained, 0.0)


def test_coherence_drops_on_unpredicted_motion():
    auditor = CoherenceAuditor(CGAConfig())
    current = np.full(NUM_DIMENSIONS, 0.9)

    # Predict that nothing moves, then move.
    auditor.record_prediction(current, np.zeros(NUM_DIMENSIONS), np.zeros(NUM_DIMENSIONS))
    actual = current.copy()
    actual[3] -= 0.4
    coherence, unexplained = auditor.audit(actual)

    assert coherence < 1.0
    assert unexplained[3] == pytest.approx(-0.4)


def test_coherence_flags_injected_attack_as_unexplained():
    """An attack is motion T_c never predicted, so it must show up in Λ_c."""
    engine = CyberGenesisEngine()
    engine.process_tick()
    engine.process_tick()

    attacked = engine.inject_attack("ddos", severity=0.7)
    assert attacked.coherence < 1.0
    assert np.any(np.abs(attacked.unexplained_vector) > 0.0)


def test_coherence_tracks_running_mean():
    auditor = CoherenceAuditor(CGAConfig())
    current = np.full(NUM_DIMENSIONS, 0.8)
    predicted = auditor.record_prediction(current, np.zeros(NUM_DIMENSIONS), np.zeros(NUM_DIMENSIONS))
    auditor.audit(predicted)
    assert auditor.mean_coherence == pytest.approx(1.0)

    auditor.reset()
    assert auditor.mean_coherence == 1.0


# ---------------------------------------------------------------------------
# T_c self-correction from coherence misses
# ---------------------------------------------------------------------------

def _surprising_host(engine: CyberGenesisEngine) -> None:
    """Drive the engine with telemetry the authored coupling does not predict."""
    engine.process_tick(TelemetryInput(raw_values={"compute": 0.55}))
    engine.process_tick(TelemetryInput(raw_values={"memory": 0.35}))
    engine.process_tick(TelemetryInput(raw_values={"data": 0.40}))


def test_coupling_frozen_by_default():
    engine = CyberGenesisEngine()
    before = engine.get_transformation_matrix().as_array()

    _surprising_host(engine)

    assert np.allclose(before, engine.get_transformation_matrix().as_array())


def test_coupling_adapts_when_rate_enabled():
    config = CGAConfig(coupling_adaptation_rate=0.05)
    engine = CyberGenesisEngine(config)
    before = engine.get_transformation_matrix().as_array()

    _surprising_host(engine)

    after = engine.get_transformation_matrix().as_array()
    assert not np.allclose(before, after)
    assert np.all(np.diag(after) == 0.0)
    assert after.min() >= 0.0 and after.max() <= 1.0


def test_correction_strengthens_understated_edge():
    """A degraded source delivering more damage than predicted must raise i→j."""
    auditor = CoherenceAuditor(CGAConfig())

    residual = np.zeros(NUM_DIMENSIONS)
    residual[0] = -0.5  # source is degraded
    auditor.record_prediction(
        np.full(NUM_DIMENSIONS, 0.9), np.zeros(NUM_DIMENSIONS), residual
    )

    unexplained = np.zeros(NUM_DIMENSIONS)
    unexplained[4] = -0.2  # target fell further than the model claimed

    correction = auditor.suggest_coupling_correction(unexplained, rate=0.1)
    assert correction[0, 4] > 0.0


def test_correction_weakens_overstated_edge():
    auditor = CoherenceAuditor(CGAConfig())

    residual = np.zeros(NUM_DIMENSIONS)
    residual[0] = -0.5
    auditor.record_prediction(
        np.full(NUM_DIMENSIONS, 0.9), np.zeros(NUM_DIMENSIONS), residual
    )

    unexplained = np.zeros(NUM_DIMENSIONS)
    unexplained[4] = 0.2  # target held up better than the model claimed

    correction = auditor.suggest_coupling_correction(unexplained, rate=0.1)
    assert correction[0, 4] < 0.0


def test_correction_is_zero_without_a_miss():
    auditor = CoherenceAuditor(CGAConfig())
    correction = auditor.suggest_coupling_correction(np.zeros(NUM_DIMENSIONS), rate=0.1)
    assert not np.any(correction)


def test_correction_is_zero_without_a_diverged_source():
    auditor = CoherenceAuditor(CGAConfig())
    auditor.record_prediction(
        np.ones(NUM_DIMENSIONS), np.zeros(NUM_DIMENSIONS), np.zeros(NUM_DIMENSIONS)
    )
    unexplained = np.zeros(NUM_DIMENSIONS)
    unexplained[2] = -0.3

    assert not np.any(auditor.suggest_coupling_correction(unexplained, rate=0.1))


# ---------------------------------------------------------------------------
# K_c — scope cost
# ---------------------------------------------------------------------------

def test_nullification_cost_prices_hubs_above_leaves():
    """Equal error on a hub must cost more to blind than on a leaf."""
    nullifier = DomainNullifier(CGAConfig())
    matrix = TransformationMatrix().as_array()

    divergence = np.zeros(NUM_DIMENSIONS)
    identity = DIMENSION_INDEX["identity"]
    recovery = DIMENSION_INDEX["recovery"]
    divergence[identity] = -0.3
    divergence[recovery] = -0.3

    cost = nullifier.compute_nullification_cost(divergence, matrix)
    assert cost[identity] > cost[recovery]


def test_nullification_cost_zero_for_quiet_dimension():
    nullifier = DomainNullifier(CGAConfig())
    matrix = TransformationMatrix().as_array()
    cost = nullifier.compute_nullification_cost(np.zeros(NUM_DIMENSIONS), matrix)
    assert np.allclose(cost, 0.0)


def test_auto_nullify_blocked_by_expensive_blind_spot():
    matrix = TransformationMatrix().as_array()
    identity = DIMENSION_INDEX["identity"]

    divergence = np.full(NUM_DIMENSIONS, 0.005)

    unpriced = DomainNullifier(CGAConfig())
    unpriced.auto_nullify_irrelevant(divergence, threshold=0.01)
    assert unpriced.get_domain_vector().activations[identity] == 0.0

    priced = DomainNullifier(CGAConfig())
    priced.auto_nullify_irrelevant(
        divergence, threshold=0.01, coupling_matrix=matrix, max_cost=0.006
    )
    assert priced.get_domain_vector().activations[identity] == 1.0


def test_assessment_exposes_nullification_cost():
    engine = CyberGenesisEngine()
    engine.process_tick()
    assessment = engine.inject_attack("identity_compromise", severity=0.5)

    identity = DIMENSION_INDEX["identity"]
    assert assessment.nullification_cost[identity] > 0.0
    assert len(assessment.nullification_cost) == NUM_DIMENSIONS


# ---------------------------------------------------------------------------
# Permission debt
# ---------------------------------------------------------------------------

def _denied_state() -> tuple[SecurityState, SecurityBaseline]:
    baseline = SecurityBaseline(
        reference=np.ones(NUM_DIMENSIONS),
        lower_bound=np.full(NUM_DIMENSIONS, 0.7),
        upper_bound=np.ones(NUM_DIMENSIONS),
    )
    breached = SecurityState(vector=np.full(NUM_DIMENSIONS, 0.2))
    return breached, baseline


def test_permission_returns_instantly_by_default():
    config = CGAConfig()
    genesis = GenesisPermission(config)
    breached, baseline = _denied_state()
    clean = SecurityState(vector=np.ones(NUM_DIMENSIONS))

    assert genesis.evaluate(breached, baseline, cci=0.0)[0] == 0.0
    assert genesis.evaluate(clean, baseline, cci=0.0)[0] == 1.0
    assert genesis.debt == 0.0


def test_permission_debt_withholds_trust_after_denial():
    config = CGAConfig(permission_debt_accrual=1.0, permission_debt_repayment=0.5)
    genesis = GenesisPermission(config)
    breached, baseline = _denied_state()
    clean = SecurityState(vector=np.ones(NUM_DIMENSIONS))

    assert genesis.evaluate(breached, baseline, cci=0.0)[0] == 0.0
    assert genesis.debt == pytest.approx(1.0)

    # One clean tick repays half the debt — still not trusted.
    assert genesis.evaluate(clean, baseline, cci=0.0)[0] == 0.0
    assert genesis.debt == pytest.approx(0.5)

    # Second clean tick clears it.
    assert genesis.evaluate(clean, baseline, cci=0.0)[0] == 1.0
    assert genesis.debt == pytest.approx(0.0)


def test_permission_debt_is_bounded():
    config = CGAConfig(
        permission_debt_accrual=1.0,
        permission_debt_repayment=0.5,
        permission_debt_max=2.0,
    )
    genesis = GenesisPermission(config)
    breached, baseline = _denied_state()

    for _ in range(20):
        genesis.evaluate(breached, baseline, cci=0.0)

    assert genesis.debt == pytest.approx(2.0)


def test_permission_evaluated_once_per_cycle():
    """Debt is stateful, so Encrypt-IC must not charge the same tick twice."""
    config = CGAConfig(permission_debt_accrual=1.0)
    engine = CyberGenesisEngine(config)
    engine.process_tick()

    assessment = engine.inject_attack("ransomware", severity=0.9)
    assert assessment.permission == 0.0
    assert assessment.permission_debt == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------

def test_dashboard_carries_reflexive_fields():
    engine = CyberGenesisEngine()
    engine.process_tick()
    engine.inject_attack("supply_chain", severity=0.5)

    dash = engine.get_dashboard()
    assert "coherence" in dash
    assert "mean_coherence" in dash
    assert "permission_debt" in dash
    assert "origin_hypotheses" in dash
    assert "nullification_cost" in dash
    assert len(dash["nullification_cost"]) == NUM_DIMENSIONS


def test_summary_carries_likely_origin():
    engine = CyberGenesisEngine()
    engine.process_tick()
    assessment = engine.inject_attack("insider_threat", severity=0.6)

    summary = assessment.summary()
    assert summary["likely_origin"] == "Trust"
    assert "coherence" in summary
    assert "permission_debt" in summary


def test_reset_restores_authored_coupling():
    config = CGAConfig(coupling_adaptation_rate=0.1)
    engine = CyberGenesisEngine(config)
    authored = TransformationMatrix().as_array()

    _surprising_host(engine)
    assert not np.allclose(authored, engine.get_transformation_matrix().as_array())

    engine.reset()
    assert np.allclose(authored, engine.get_transformation_matrix().as_array())


def test_reflexive_operators_survive_telemetry_path():
    engine = CyberGenesisEngine()
    for _ in range(3):
        engine.process_tick(TelemetryInput(raw_values={"compute": 0.95, "memory": 0.93}))

    degraded = engine.process_tick(
        TelemetryInput(raw_values={"compute": 0.30, "memory": 0.25})
    )
    assert degraded.origin_hypotheses
    assert 0.0 <= degraded.coherence <= 1.0
