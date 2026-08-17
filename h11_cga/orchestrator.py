"""
H¹¹-CGA Orchestrator
=====================

The main control loop connecting all five engines in the closed loop:
SENSE → DIVERGE → LIMIT → CONVERGE → ENCRYPT → RE-EVAL → SENSE

This is the primary entry point for the H¹¹ Cyber Genesis Architecture.
"""

from __future__ import annotations

import time
from typing import Optional, List

import numpy as np

from h11_cga.types import (
    CGAConfig, ThreatAssessment, SecurityEvent, TelemetryInput,
    SecurityState, SecurityBaseline, DivergenceResult, DomainVector,
    SystemStatus, HSAZone, ActionUrgency,
    DivergenceClassification,
    NUM_DIMENSIONS, DIMENSION_INDEX,
)
from h11_cga.core.transformation_matrix import TransformationMatrix
from h11_cga.core.cyber_genesis_equation import CyberGenesisEquation
from h11_cga.core.barrier import BarrierCertificate
from h11_cga.core.advanced import SelfHealingProjector
from h11_cga.engines.sense import SenseEngine
from h11_cga.engines.diverge import DivergeEngine
from h11_cga.engines.limit import LimitEngine as LimitEngineWrapper
from h11_cga.engines.converge import ConvergeEngine
from h11_cga.engines.encrypt import EncryptICEngine


class CyberGenesisEngine:
    """The main control loop orchestrator for H¹¹-CGA.

    Connects SENSE -> DIVERGE -> LIMIT -> CONVERGE -> ENCRYPT -> RE-EVAL.
    Each call to ``process_tick`` executes one full cycle of the architecture.
    """

    def __init__(self, config: Optional[CGAConfig] = None) -> None:
        """Initialize the orchestrator and all five engines."""
        if config is None:
            config = CGAConfig()
        self._config = config

        # Core math components — T_c is shared with CCI so cascade math
        # and state propagation use the same 121 influence nodes.
        self._transform = TransformationMatrix()
        self._equation = CyberGenesisEquation(config)
        self._barrier = BarrierCertificate(config)
        self._healer = SelfHealingProjector(config)

        # Five subsystem engines
        self._sense = SenseEngine(config)
        self._diverge = DivergeEngine(config)
        self._limit = LimitEngineWrapper(config)
        self._converge = ConvergeEngine(config, coupling_matrix=self._transform.as_array())
        self._encrypt = EncryptICEngine(config)

        nominal = np.ones(NUM_DIMENSIONS)
        self._sense.update_baseline(nominal, tolerance=0.3)

        self._tick_count: int = 0
        self._assessment_history: List[ThreatAssessment] = []
        self._event_log: List[dict] = []
        self._last_dr: float = 0.0
        self._last_dr_adjusted: float = 0.0
        self._last_tick_time: float = time.time()
        self._previous_state: Optional[SecurityState] = None

    def process_tick(
        self, telemetry: Optional[TelemetryInput] = None
    ) -> ThreatAssessment:
        """Execute ONE FULL CYCLE of the H¹¹-CGA control loop.

        Steps:
            1. SENSE    — ingest telemetry → current state
            2. DIVERGE  — DSA + DR^(a) (domain-adjusted via DNT)
            3. LIMIT    — ULE + HSA → distance to failure
            4. CONVERGE — CCI + ΔCR → prioritized response actions
            5. ENCRYPT  — Genesis + DNT → permission, domain metric
            6. EQUATION — compute G_c(t) → system status
            7. BARRIER  — h(X_c) forward-invariance of Ω_c
            8. RE-EVAL  — T_c cascade + ΔCR convergence + regeneration
                          fed back into SENSE for the next cycle

        Returns:
            Complete ThreatAssessment for this cycle (pre-regeneration).
        """
        now = time.time()
        self._last_tick_time = now
        # One process_tick is one discrete control cycle, independent of
        # wall-clock spacing between calls (tests vs live monitor).
        dt = 1.0

        # --- 1. SENSE ---
        if telemetry is not None:
            self._sense.ingest(telemetry)
        current_state = self._sense.get_current_state()
        baseline = self._sense.get_baseline()

        # --- 2. DIVERGE (W_c(a) from last ENCRYPT / current DNT) ---
        domain_metric = self._encrypt.get_domain_nullifier().compute_domain_metric()
        divergence, dr_value, dr_adjusted, dr_rate = self._diverge.analyze(
            current_state, baseline, domain_metric=domain_metric, dt=dt
        )
        self._last_dr = dr_value
        self._last_dr_adjusted = dr_adjusted

        # --- 3. LIMIT ---
        hsa_coordinate, hsa_zone, security_buffer, limit_utilization, within_limits = (
            self._limit.evaluate(dr_value, divergence.divergence_vector, dt=dt)
        )

        # --- 4. CONVERGE ---
        errors = np.abs(divergence.divergence_vector)
        actions, cci_value, cci_subcritical, cascade_paths = self._converge.process(
            divergence, hsa_zone, errors
        )

        # --- 5. ENCRYPT ---
        classification, permission, domain_metric, domain_vector = (
            self._encrypt.enforce_boundary(current_state, baseline, cci_value)
        )

        # Recompute domain-adjusted DR with the post-ENCRYPT W_c(a) so
        # G_c(t) uses the architecture term DR_c^(a) = W_c(a) · DR_c
        # from this cycle's boundary decision.
        dr_adjusted = self._diverge.dr.compute_domain_adjusted_dr(dr_value, domain_metric)
        self._last_dr_adjusted = dr_adjusted

        # --- 6. EQUATION ---
        hsa_positive = max(0.0, hsa_coordinate)
        gc_value, gc_terms = self._equation.compute_with_breakdown(
            permission=permission,
            dr_adjusted=dr_adjusted,
            dr_rate=abs(dr_rate),
            hsa_positive=hsa_positive,
            cci=cci_value,
        )
        status = self._equation.classify_status(gc_value, permission)
        safety_conditions = self._equation.get_safety_conditions(
            permission, hsa_coordinate, cci_value, dr_adjusted
        )

        # --- 7. BARRIER ---
        prev = self._previous_state if self._previous_state is not None else current_state
        barrier_invariant, barrier_value, _cbf = self._barrier.verify_invariance(
            current_state, prev, baseline, dt=dt
        )
        self._previous_state = current_state.copy()
        time_to_boundary = self._limit.get_time_to_boundary()

        # --- 8. RE-EVAL / closed loop (does not rewrite this tick's assessment) ---
        regeneration_energy = 0.0
        if self._config.closed_loop_enabled and telemetry is None:
            regeneration_energy =             self._apply_closed_loop(
                current_state=current_state,
                baseline=baseline,
                divergence=divergence,
                domain_vector=domain_vector,
                actions=actions,
                permission=permission,
                hsa_zone=hsa_zone,
                dt=dt,
            )

        assessment = ThreatAssessment(
            current_state=current_state,
            baseline=baseline,
            divergence=divergence,
            dr_value=dr_value,
            dr_adjusted=dr_adjusted,
            dr_rate=dr_rate,
            hsa_coordinate=hsa_coordinate,
            hsa_zone=hsa_zone,
            security_buffer=security_buffer,
            limit_utilization=limit_utilization,
            within_limits=within_limits,
            cci_value=cci_value,
            cci_threshold=self._config.cci_threshold,
            cci_subcritical=cci_subcritical,
            critical_cascade_paths=cascade_paths,
            permission=permission,
            domain_vector=domain_vector,
            domain_metric=domain_metric,
            genesis_value=gc_value,
            genesis_terms=gc_terms,
            encrypt_classification=classification,
            barrier_value=barrier_value,
            barrier_invariant=barrier_invariant,
            time_to_boundary=time_to_boundary,
            safety_conditions=safety_conditions,
            regeneration_energy=regeneration_energy,
            status=status,
            recommended_actions=actions,
            timestamp=now,
        )

        self._assessment_history.append(assessment)
        self._event_log.append({
            "tick": self._tick_count,
            "timestamp": assessment.timestamp,
            "status": status.value,
            "genesis_value": gc_value,
            "encrypt_classification": classification.value,
            "barrier_value": barrier_value,
        })
        self._tick_count += 1

        return assessment

    def _apply_closed_loop(
        self,
        current_state: SecurityState,
        baseline: SecurityBaseline,
        divergence: DivergenceResult,
        domain_vector: DomainVector,
        actions,
        permission: float,
        hsa_zone: HSAZone,
        dt: float,
    ) -> float:
        """Feed ENCRYPT / CONVERGE / T_c outputs back into SENSE.

        1. Cascade: residual divergence spreads through T_c, gated by a(t)
        2. Convergence: ΔCR actions pull degraded dimensions toward X_c*
        3. Regeneration: R_genesis projects onto Ω_c when recovering
        """
        gain_dt = min(max(dt, 1e-6), 1.0) * self._config.cascade_gain
        residual = current_state.vector - baseline.reference
        cascaded = self._transform.propagate_state(
            current_state,
            residual,
            dt=gain_dt,
            domain_vector=domain_vector,
        )
        vec = cascaded.vector.copy()

        urgency_scale = {
            ActionUrgency.LOW: 0.08,
            ActionUrgency.MEDIUM: 0.18,
            ActionUrgency.HIGH: 0.40,
            ActionUrgency.CRITICAL: 0.60,
        }
        conv_gain = self._config.convergence_gain
        for action in actions:
            if action.dimension < 0:
                continue
            i = action.dimension
            step = urgency_scale.get(action.urgency, 0.1) * conv_gain
            vec[i] = vec[i] + step * (baseline.reference[i] - vec[i])

        # Encrypt-IC N_0 isolates unauthorized *execution*; MCC state X_c(t)
        # remains the measured security state so ΔCR can still converge it.

        regeneration_energy = 0.0
        recovering = divergence.classification == DivergenceClassification.RECOVERING
        if (
            self._config.regeneration_enabled
            and recovering
            and hsa_zone == HSAZone.CONTROLLED
            and permission == 1.0
        ):
            candidate = SecurityState(vector=np.clip(vec, 0.0, 1.0), timestamp=time.time())
            restored, energy, _corr = self._healer.project_to_permissible_manifold(
                candidate, baseline
            )
            vec = restored.vector
            regeneration_energy = energy

        new_state = SecurityState(
            vector=np.clip(vec, 0.0, 1.0),
            timestamp=time.time(),
        )
        self._sense.current_state = new_state
        return regeneration_energy

    # ------------------------------------------------------------------
    # Event injection
    # ------------------------------------------------------------------

    def inject_event(self, event: SecurityEvent) -> ThreatAssessment:
        """Apply a security event to the MCC state and run a full tick."""
        self._sense.get_state_space().apply_event(event)
        return self.process_tick()

    def inject_attack(
        self, attack_name: str, severity: float = 0.5
    ) -> ThreatAssessment:
        """Inject a predefined attack pattern.

        Supported attacks:
            - identity_compromise
            - privilege_escalation
            - data_exfiltration
            - ddos
            - insider_threat
            - zero_day
            - lateral_movement
            - ransomware
            - supply_chain
        """
        patterns = {
            "identity_compromise": {
                "identity": -1.0, "trust": -0.7, "authorization": -0.5
            },
            "privilege_escalation": {
                "authorization": -1.0, "execution": -0.8, "compute": -0.6
            },
            "data_exfiltration": {
                "data": -1.0, "network": -0.5, "recovery": -0.3
            },
            "ddos": {
                "network": -1.0, "resource": -0.9, "compute": -0.4
            },
            "insider_threat": {
                "trust": -1.0, "identity": -0.3, "governance": -0.6, "data": -0.4
            },
            "zero_day": {
                "execution": -1.0, "memory": -0.8, "compute": -0.7, "recovery": -0.5
            },
            "lateral_movement": {
                "network": -0.6, "compute": -1.0, "memory": -0.5, "authorization": -0.4
            },
            "ransomware": {
                "data": -1.0, "execution": -0.8, "recovery": -0.9, "resource": -0.5
            },
            "supply_chain": {
                "trust": -0.9, "execution": -0.7, "governance": -0.6, "identity": -0.4
            },
        }

        impact = np.zeros(NUM_DIMENSIONS)
        pattern = patterns.get(attack_name.lower(), {})
        target_dims = []
        for dim_name, multiplier in pattern.items():
            idx = DIMENSION_INDEX.get(dim_name)
            if idx is not None:
                impact[idx] = multiplier * severity
                target_dims.append(idx)

        event = SecurityEvent(
            event_type=f"attack_{attack_name}",
            source="external",
            target_dimensions=target_dims,
            impact=impact,
            severity=severity,
            metadata={"attack_pattern": attack_name},
            timestamp=time.time(),
        )
        return self.inject_event(event)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_system_status(self) -> SystemStatus:
        """Return the latest system status."""
        if not self._assessment_history:
            return SystemStatus.PERMITTED
        return self._assessment_history[-1].status

    def get_genesis_value(self) -> float:
        """Return the latest G_c value."""
        if not self._assessment_history:
            return 1.0
        return self._assessment_history[-1].genesis_value

    def get_dashboard(self) -> dict:
        """Return a complete snapshot of the current system state."""
        if not self._assessment_history:
            return {"tick": 0, "status": "NO_DATA"}

        latest = self._assessment_history[-1]
        return {
            "tick": self._tick_count,
            "status": latest.status.value,
            "genesis_value": latest.genesis_value,
            "permission": latest.permission,
            "dr_value": latest.dr_value,
            "dr_adjusted": latest.dr_adjusted,
            "dr_rate": latest.dr_rate,
            "hsa_coordinate": latest.hsa_coordinate,
            "hsa_zone": latest.hsa_zone.value,
            "security_buffer": latest.security_buffer,
            "limit_utilization": latest.limit_utilization,
            "cci_value": latest.cci_value,
            "cci_subcritical": latest.cci_subcritical,
            "domain_metric": latest.domain_metric,
            "active_domains": latest.domain_vector.active_domains,
            "actions_count": len(latest.recommended_actions),
            "encrypt_classification": latest.encrypt_classification.value,
            "barrier_value": latest.barrier_value,
            "barrier_invariant": latest.barrier_invariant,
            "time_to_boundary": latest.time_to_boundary,
            "safety_conditions": latest.safety_conditions,
            "regeneration_energy": latest.regeneration_energy,
        }

    def get_assessment_history(self) -> List[ThreatAssessment]:
        """Return all past threat assessments."""
        return list(self._assessment_history)

    def get_transformation_matrix(self) -> TransformationMatrix:
        """Return the underlying 11×11 transformation matrix."""
        return self._transform

    def set_domain_activation(self, dimension: str | int, level: float) -> None:
        """Set domain activation level (delegates to Encrypt-IC engine)."""
        self._encrypt.get_domain_nullifier().activate_domain(dimension, level)

    def reset(self) -> None:
        """Reset all engines and counters."""
        self._tick_count = 0
        self._assessment_history.clear()
        self._event_log.clear()
        self._last_dr = 0.0
        self._last_dr_adjusted = 0.0
        self._last_tick_time = time.time()
        self._previous_state = None

        self._sense.reset()
        self._diverge.reset()
        self._limit.reset()
        self._converge.reset()
        self._encrypt.reset()

        nominal = np.ones(NUM_DIMENSIONS)
        self._sense.update_baseline(nominal, tolerance=0.3)
