from __future__ import annotations
import logging
import numpy as np
from h11_cga.types import CGAConfig, DomainVector, NUM_DIMENSIONS, DIMENSION_INDEX, DIMENSION_NAMES

logger = logging.getLogger(__name__)

class DomainNullifier:
    """
    Manages Domain Nullification (DNT) functionality allowing dimensions 
    to be selectively reduced or ignored mathematically during emergencies.
    """
    def __init__(self, config: CGAConfig, initial_activations: np.ndarray | None = None):
        self.config = config
        if initial_activations is None:
            activations = np.ones(NUM_DIMENSIONS)
        else:
            activations = initial_activations.copy()
        self._domain_vector = DomainVector(activations=activations)

    def compute_domain_metric(self, domain_vector: DomainVector | None = None, weights: np.ndarray | None = None) -> float:
        """
        Computes the weighted domain metric W_c(a).
        """
        dv = domain_vector if domain_vector is not None else self._domain_vector
        w = weights if weights is not None else self.config.domain_weights
        return float(np.dot(dv.activations, w))

    def apply_nullification(self, dr: float, domain_vector: DomainVector | None = None) -> float:
        """
        Adjusts Divergence Rate (DR) relative to the active domains.
        DR_c^(a) = W_c(a) * DR_c
        """
        w_c = self.compute_domain_metric(domain_vector)
        return w_c * dr

    def nullify_domain(self, dimension: int | str) -> None:
        """Sets the designated dimension's activation mathematically to 0."""
        idx = dimension if isinstance(dimension, int) else DIMENSION_INDEX.get(dimension.lower())
        if idx is not None and 0 <= idx < NUM_DIMENSIONS:
            self._domain_vector.nullify(idx)
            logger.info(f"Nullified domain index {idx} ({DIMENSION_NAMES[idx]}).")

    def activate_domain(self, dimension: int | str, level: float = 1.0) -> None:
        """Sets or restores the designated dimension's activation level."""
        idx = dimension if isinstance(dimension, int) else DIMENSION_INDEX.get(dimension.lower())
        if idx is not None and 0 <= idx < NUM_DIMENSIONS:
            self._domain_vector.activate(idx, level)
            logger.info(f"Activated domain index {idx} ({DIMENSION_NAMES[idx]}) to level {level}.")

    def get_domain_vector(self) -> DomainVector:
        """Returns a snapshot of the current domain activation vector."""
        return DomainVector(activations=self._domain_vector.activations.copy())

    def set_domain_vector(self, dv: DomainVector) -> None:
        """Overwrites the domain vector directly."""
        self._domain_vector = DomainVector(activations=dv.activations.copy())

    def compute_complexity_reduction(self) -> float:
        """Returns the ratio of actively engaged dimensions vs total dimensions."""
        return self._domain_vector.complexity_ratio

    def auto_nullify_irrelevant(self, divergence: np.ndarray, threshold: float = 0.01) -> list[str]:
        """
        Automatically shuts down evaluation of domains where divergence is below the threshold,
        freeing resources.
        """
        nullified = []
        for i in range(NUM_DIMENSIONS):
            if abs(divergence[i]) < threshold and self._domain_vector.activations[i] > 0:
                self.nullify_domain(i)
                nullified.append(DIMENSION_NAMES[i])
        
        if nullified:
            logger.debug(f"Auto-nullified {len(nullified)} irrelevant domains: {nullified}")
        return nullified
