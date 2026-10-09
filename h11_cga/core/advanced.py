"""
H¹¹ Advanced Core — Cryptographic State Prover & Self-Healing Projector
========================================================================

Mathematical Hardening Extensions:
1. StateIntegrityProver: Cryptographic HMAC-SHA3-512 signature verification for 11-D state vectors.
2. SelfHealingProjector: Algebraic Projection Operator R_genesis(X_c) restoring degraded states to Ω_c.
3. DynamicCouplingEngine: Matrix exponential propagation e^(T_c · t) across 121 influence nodes.
"""

from __future__ import annotations

import hashlib
import secrets
import hmac
import logging
import time
from typing import Dict, Any, Tuple, Optional

import numpy as np

from h11_cga.types import (
    SecurityState,
    SecurityBaseline,
    CGAConfig,
    NUM_DIMENSIONS,
    DIMENSION_NAMES,
)

logger = logging.getLogger(__name__)


class StateIntegrityProver:
    """
    Quantum-Resilient HMAC-SHA3-512 Cryptographic State Integrity Prover.

    Generates and verifies cryptographic signatures over the 11-D Security State Vector
    to prevent memory injection or in-flight tampering of telemetry coordinates.
    """

    def __init__(self, secret_key: Optional[bytes] = None) -> None:
        if secret_key is not None and (not isinstance(secret_key, bytes) or len(secret_key) < 32):
            raise ValueError("HMAC key must contain at least 32 bytes")
        self.secret_key = secret_key if secret_key is not None else secrets.token_bytes(64)

    def sign_state(self, state: SecurityState) -> str:
        """
        Generate HMAC-SHA3-512 signature string for a SecurityState object.
        """
        raw_bytes = state.vector.tobytes() + str(state.timestamp).encode("utf-8")
        signature = hmac.new(self.secret_key, raw_bytes, hashlib.sha3_512).hexdigest()
        return signature

    def verify_state(self, state: SecurityState, signature: str) -> bool:
        """
        Verify that a SecurityState object matches its expected signature.
        """
        expected = self.sign_state(state)
        return hmac.compare_digest(expected, signature)


class SelfHealingProjector:
    """
    Algebraic Self-Healing State Projection Operator R_genesis(X_c).

    Given a degraded or perturbed state X_c ∉ Ω_c, computes the minimal Euclidean distance
    projection R_genesis(X_c) = argmin_{x̂ ∈ Ω_c} ‖X_c - x̂‖, instantly restoring all 11 dimensions
    back into the permissible operational corridor [L_c, U_c].
    """

    def __init__(self, config: CGAConfig) -> None:
        self.config = config

    def project_to_permissible_manifold(
        self, state: SecurityState, baseline: SecurityBaseline
    ) -> Tuple[SecurityState, float, np.ndarray]:
        """
        Apply algebraic projection R_genesis(X_c) to restore state integrity.

        Args:
            state: Current degraded state X_c(t).
            baseline: SecurityBaseline envelope [L_c, U_c].

        Returns:
            Tuple of (restored_state, energy_restored, correction_vector).
        """
        curr_vec = state.vector.copy()

        # Compute element-wise projection onto box constraints [lower_bound, upper_bound]
        restored_vec = np.clip(curr_vec, baseline.lower_bound, baseline.upper_bound)

        # Compute energy restored (Euclidean distance shifted)
        correction_vec = restored_vec - curr_vec
        energy_restored = float(np.linalg.norm(correction_vec))

        restored_state = SecurityState(
            vector=restored_vec, timestamp=time.time()
        )

        if energy_restored > 0:
            logger.info(f"Self-Healing Projector R_genesis applied: Energy restored = {energy_restored:.4f}")

        return restored_state, energy_restored, correction_vec


class DynamicCouplingEngine:
    """
    Dynamic Matrix Exponential Engine computing perturbation propagation e^(T_c · t)
    across the 121 influence nodes of the 11×11 Transformation Matrix T_c.
    """

    def __init__(self, transformation_matrix: np.ndarray) -> None:
        self.T_c = transformation_matrix

    def compute_matrix_exponential(self, t: float = 1.0) -> np.ndarray:
        """
        Compute matrix exponential e^(T_c · t) via Taylor series approximation.
        """
        A = self.T_c * t
        result = np.eye(NUM_DIMENSIONS)
        term = np.eye(NUM_DIMENSIONS)

        for n in range(1, 8):
            term = (term @ A) / float(n)
            result = result + term

        return result

    def project_cascade_decay(
        self, initial_perturbation: np.ndarray, t: float = 1.0
    ) -> np.ndarray:
        """
        Project perturbation vector after time t under matrix exponential dynamics.
        """
        exp_matrix = self.compute_matrix_exponential(t)
        projected = exp_matrix @ initial_perturbation
        return np.clip(projected, -1.0, 1.0)
