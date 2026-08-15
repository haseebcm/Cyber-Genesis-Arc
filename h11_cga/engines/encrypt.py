"""
H¹¹ ENCRYPT-IC — Adaptive Security Boundary
=============================================

The security boundary layer that classifies inputs as authorized,
uncertain, divergent, or unauthorized, and applies domain nullification
and genesis permission enforcement.
"""

from __future__ import annotations

import logging
import time

import numpy as np

from h11_cga.types import (
    SecurityState,
    SecurityBaseline,
    EncryptICClassification,
    DomainVector,
    CGAConfig,
    NUM_DIMENSIONS,
)
from h11_cga.core.genesis import GenesisPermission
from h11_cga.core.domain_nullification import DomainNullifier

logger = logging.getLogger(__name__)


class EncryptICEngine:
    """H¹¹ ENCRYPT-IC — Adaptive Security Boundary."""

    def __init__(self, config: CGAConfig) -> None:
        self.config = config
        self.genesis = GenesisPermission(config)
        self.nullifier = DomainNullifier(config)

    def classify_input(
        self,
        state: SecurityState,
        baseline: SecurityBaseline,
        cci: float,
    ) -> EncryptICClassification:
        """Classify input based on permission and divergence context."""
        # Compute permission via genesis
        permission, _details = self.genesis.evaluate(state, baseline, cci)

        if permission < 0.5:
            return EncryptICClassification.UNAUTHORIZED

        # Measure divergence magnitude
        div_mag = float(np.linalg.norm(state.vector - baseline.reference))

        if div_mag < 0.3:
            return EncryptICClassification.AUTHORIZED
        elif div_mag < 0.8:
            return EncryptICClassification.UNCERTAIN
        else:
            return EncryptICClassification.DIVERGENT

    def enforce_boundary(
        self,
        state: SecurityState,
        baseline: SecurityBaseline,
        cci: float,
    ) -> tuple[EncryptICClassification, float, float, DomainVector]:
        """Full boundary enforcement.

        Returns:
            (classification, permission, domain_metric, domain_vector)
        """
        classification = self.classify_input(state, baseline, cci)

        # Compute permission
        permission, _details = self.genesis.evaluate(state, baseline, cci)

        # Get domain vector and compute metric
        domain_vector = self.nullifier.get_domain_vector()
        domain_metric = self.nullifier.compute_domain_metric(domain_vector)

        # If unauthorized, nullify all domains
        if classification == EncryptICClassification.UNAUTHORIZED:
            for i in range(NUM_DIMENSIONS):
                domain_vector.nullify(i)
            domain_metric = 0.0

        return classification, permission, domain_metric, domain_vector

    def nullify_unauthorized(
        self,
        classification: EncryptICClassification,
        state: SecurityState,
    ) -> SecurityState:
        """Apply nullification or constraint based on classification.

        UNAUTHORIZED → null state (N_0)
        DIVERGENT → constrained to half values
        Otherwise → pass through
        """
        if classification == EncryptICClassification.UNAUTHORIZED:
            return SecurityState(
                vector=np.zeros(NUM_DIMENSIONS), timestamp=time.time()
            )
        elif classification == EncryptICClassification.DIVERGENT:
            constrained = np.clip(state.vector, 0.3, 1.0)
            return SecurityState(vector=constrained, timestamp=time.time())
        else:
            return state

    def get_domain_nullifier(self) -> DomainNullifier:
        """Get the underlying domain nullifier."""
        return self.nullifier

    def reset(self) -> None:
        """Reset the ENCRYPT-IC engine."""
        self.genesis = GenesisPermission(self.config)
        self.nullifier = DomainNullifier(self.config)
        logger.info("EncryptICEngine reset")
