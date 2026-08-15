"""
H¹¹-CGA Orchestrator
=====================

The main control loop connecting all five engines in the closed loop:
SENSE → DIVERGE → LIMIT → CONVERGE → ENCRYPT → re-evaluate → SENSE

This is the primary entry point for the H¹¹ Cyber Genesis Architecture.
"""

from __future__ import annotations

import time
from typing import Optional, List

import numpy as np

from h11_cga.types import (
    CGAConfig, ThreatAssessment, SecurityEvent, TelemetryInput,
    SecurityState, SecurityBaseline, DivergenceResult, DomainVector,
    SystemStatus, HSAZone, CascadePath, ResponseAction,
    NUM_DIMENSIONS, DIMENSION_NAMES, DIMENSION_INDEX,
)
from h11_cga.core.transformation_matrix import TransformationMatrix
from h11_cga.core.cyber_genesis_equation import CyberGenesisEquation
from h11_cga.engines.sense import SenseEngine
from h11_cga.engines.diverge import DivergeEngine
from h11_cga.engines.limit import LimitEngine as LimitEngineWrapper
from h11_cga.engines.converge import ConvergeEngine
from h11_cga.engines.encrypt import EncryptICEngine


class CyberGenesisEngine:
    """The main control loop orchestrator for H¹¹-CGA.

    Connects SENSE -> DIVERGE -> LIMIT -> CONVERGE -> ENCRYPT -> re-evaluate.
    Each call to ``process_tick`` executes one full cycle of the architecture.
    """

    def __init__(self, config: Optional[CGAConfig] = None) -> None:
        """Initialize the orchestrator and all five engines."""
        if config is None:
            config = CGAConfig()
        self._config = config

        # Core math components
        self._transform = TransformationMatrix()  # uses default 11x11 matrix
        self._equation = CyberGenesisEquation(config)

        # Five subsystem engines
        self._sense = SenseEngine(config)
        self._diverge = DivergeEngine(config)
        self._limit = LimitEngineWrapper(config)
        self._converge = ConvergeEngine(config)
        self._encrypt = EncryptICEngine(config)

        # Set up sense engine with proper baseline (state values in [0,1])
        nominal = np.ones(NUM_DIMENSIONS)
        self._sense.update_baseline(nominal, tolerance=0.3)
        self._sense.current_state = SecurityState(
            vector=nominal.copy(), timestamp=time.time()
        )

        # Tracking
        self._tick_count: int = 0
        self._assessment_history: List[ThreatAssessment] = []
        self._event_log: List[dict] = []
        self._last_dr: float = 0.0
        self._last_dr_adjusted: float = 0.0

    def process_tick(
        self, telemetry: Optional[TelemetryInput] = None
    ) -> ThreatAssessment:
        """Execute ONE FULL CYCLE of the H¹¹-CGA control loop.

        Steps:
            1. SENSE   — ingest telemetry → current state
            2. DIVERGE — DSA + DR → divergence, magnitude, acceleration
            3. LIMIT   — ULE + HSA → distance to failure
            4. CONVERGE — CCI + ΔCR → prioritized response actions
            5. ENCRYPT — Genesis + DNT → permission, domain metric
            6. EQUATION — compute G_c(t) → system status

        Returns:
            Complete ThreatAssessment for this cycle.
        """
        # --- 1. SENSE ---
        if telemetry is not None:
            self._sense.ingest(telemetry)
        current_state = self._sense.get_current_state()
        baseline = self._sense.get_baseline()

        # --- 2. DIVERGE ---
        divergence, dr_value, dr_adjusted, dr_rate = self._diverge.analyze(
            current_state, baseline
        )
        self._last_dr = dr_value
        self._last_dr_adjusted = dr_adjusted

        # --- 3. LIMIT ---
        hsa_coordinate, hsa_zone, security_buffer, limit_utilization, within_limits = (
            self._limit.evaluate(dr_value, divergence.divergence_vector)
        )

        # --- 4. CONVERGE ---
        errors = np.abs(divergence.divergence_vector)
        actions, cci_value, cci_subcritical, cascade_paths = self._converge.process(
            divergence, hsa_zone, True, errors
        )

        # --- 5. ENCRYPT ---
        classification, permission, domain_metric, domain_vector = (
            self._encrypt.enforce_boundary(current_state, baseline, cci_value)
        )

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

        # --- 7. Build ThreatAssessment ---
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
            status=status,
            recommended_actions=actions,
            timestamp=time.time(),
        )

        # --- 8. Log ---
        self._assessment_history.append(assessment)
        self._event_log.append({
            "tick": self._tick_count,
            "timestamp": assessment.timestamp,
            "status": status.value,
            "genesis_value": gc_value,
        })
        self._tick_count += 1

        return assessment

    # ------------------------------------------------------------------
    # Event injection
    # ------------------------------------------------------------------

    def inject_event(self, event: SecurityEvent) -> ThreatAssessment:
        """Apply a security event to the state and run a full tick."""
        # Apply impact directly to current state
        current = self._sense.get_current_state()
        new_vec = np.clip(current.vector + event.impact, 0.0, 1.0)
        self._sense.current_state = SecurityState(
            vector=new_vec, timestamp=time.time()
        )
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

        self._sense.reset()
        self._diverge.reset()
        self._limit.reset()
        self._converge.reset()
        self._encrypt.reset()

        # Re-establish nominal baseline
        nominal = np.ones(NUM_DIMENSIONS)
        self._sense.update_baseline(nominal, tolerance=0.3)
        self._sense.current_state = SecurityState(
            vector=nominal.copy(), timestamp=time.time()
        )
