"""
H¹¹-CGA Comprehensive Test Suite
=================================
Tests all core mathematical modules, engines, and the orchestrator control loop.
"""

import pytest
import numpy as np
import time

from h11_cga import (
    CyberGenesisEngine,
    SecurityState,
    SecurityBaseline,
    SecurityEvent,
    TelemetryInput,
    CGAConfig,
    SystemStatus,
    HSAZone,
    DivergenceClassification,
    EncryptICClassification,
    NUM_DIMENSIONS,
    DIMENSION_NAMES,
)
from h11_cga.core.mcc import SecurityStateSpace
from h11_cga.core.dsa import DirectionalDivergence
from h11_cga.core.dr import DivergenceRatio
from h11_cga.core.hsa import SingularityTracker
from h11_cga.core.ule import LimitEngine as CoreLimitEngine
from h11_cga.core.domain_nullification import DomainNullifier
from h11_cga.core.cci import CascadeAnalyzer
from h11_cga.core.genesis import GenesisPermission
from h11_cga.core.transformation_matrix import TransformationMatrix
from h11_cga.core.cyber_genesis_equation import CyberGenesisEquation


@pytest.fixture
def config():
    return CGAConfig()


def test_security_state():
    vec = np.ones(NUM_DIMENSIONS)
    state = SecurityState(vector=vec, timestamp=time.time())
    assert state.vector.shape == (11,)
    assert state["identity"] == 1.0
    assert state[0] == 1.0
    dim_dict = state.dimension_dict
    assert len(dim_dict) == 11
    assert dim_dict["Identity"] == 1.0


def test_security_baseline():
    ref = np.ones(NUM_DIMENSIONS)
    baseline = SecurityBaseline(
        reference=ref,
        lower_bound=np.full(NUM_DIMENSIONS, 0.7),
        upper_bound=np.ones(NUM_DIMENSIONS),
    )
    state_nominal = SecurityState(vector=np.ones(NUM_DIMENSIONS))
    state_degraded = SecurityState(vector=np.full(NUM_DIMENSIONS, 0.5))

    assert baseline.is_within_envelope(state_nominal) is True
    assert baseline.is_within_envelope(state_degraded) is False


def test_mcc_state_space(config):
    mcc = SecurityStateSpace(config)
    state = SecurityState(vector=np.ones(NUM_DIMENSIONS))
    mcc.update_state(state)
    assert np.array_equal(mcc.get_state_vector(), np.ones(NUM_DIMENSIONS))


def test_dsa_divergence(config):
    dsa = DirectionalDivergence(config)
    baseline = SecurityBaseline(
        reference=np.ones(NUM_DIMENSIONS),
        lower_bound=np.full(NUM_DIMENSIONS, 0.7),
        upper_bound=np.ones(NUM_DIMENSIONS),
    )
    state = SecurityState(vector=np.ones(NUM_DIMENSIONS))
    res = dsa.compute_divergence(state, baseline)
    assert res.classification == DivergenceClassification.NORMAL
    assert res.magnitude == 0.0


def test_dr_divergence_ratio(config):
    dr = DivergenceRatio(config)
    div_vec = np.zeros(NUM_DIMENSIONS)
    val = dr.compute_dr(div_vec)
    assert val == 0.0

    adj = dr.compute_domain_adjusted_dr(2.0, 0.5)
    assert adj == 1.0


def test_hsa_singularity_tracker(config):
    hsa = SingularityTracker(config)
    coord = hsa.compute_singularity_coordinate(dr=0.0)
    assert coord < 0
    assert hsa.get_zone(coord) == HSAZone.CONTROLLED


def test_ule_limit_engine(config):
    ule = CoreLimitEngine(config)
    demand = np.zeros(NUM_DIMENSIONS)
    util = ule.compute_limit_utilization(demand)
    assert util == 0.0
    assert ule.is_within_limit(util) is True


def test_domain_nullifier(config):
    dnt = DomainNullifier(config)
    metric_full = dnt.compute_domain_metric()
    assert metric_full == pytest.approx(1.0)

    dnt.nullify_domain("identity")
    metric_reduced = dnt.compute_domain_metric()
    assert metric_reduced < 1.0


def test_cascade_analyzer(config):
    cci = CascadeAnalyzer(config)
    errors = np.zeros(NUM_DIMENSIONS)
    val = cci.compute_cci(errors)
    assert val == 0.0
    assert cci.is_subcritical(val) is True


def test_genesis_permission(config):
    gen = GenesisPermission(config)
    baseline = SecurityBaseline(
        reference=np.ones(NUM_DIMENSIONS),
        lower_bound=np.full(NUM_DIMENSIONS, 0.7),
        upper_bound=np.ones(NUM_DIMENSIONS),
    )
    state = SecurityState(vector=np.ones(NUM_DIMENSIONS))
    perm = gen.compute_permission(state, baseline, 0.0, 0.0)
    assert perm == 1.0


def test_transformation_matrix():
    tm = TransformationMatrix()
    matrix = tm._matrix
    assert matrix.shape == (11, 11)
    src, tgt, val = tm.get_strongest_coupling()
    assert val > 0.0


def test_cyber_genesis_equation(config):
    cge = CyberGenesisEquation(config)
    gc = cge.compute(
        permission=1.0, dr_adjusted=0.0, dr_rate=0.0, hsa_positive=0.0, cci=0.0
    )
    assert gc == 1.0
    assert cge.classify_status(gc, permission=1.0) == SystemStatus.PERMITTED


def test_orchestrator_closed_loop():
    engine = CyberGenesisEngine()
    assessment = engine.process_tick()

    assert assessment.status == SystemStatus.PERMITTED
    assert assessment.genesis_value == 1.0
    assert assessment.permission == 1.0
    assert assessment.dr_value == 0.0

    # Inject attack
    attack_assessment = engine.inject_attack("identity_compromise", severity=0.5)
    assert attack_assessment.genesis_value < 1.0
    assert len(attack_assessment.recommended_actions) > 0

    # Verify history
    history = engine.get_assessment_history()
    assert len(history) == 2
