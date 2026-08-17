from __future__ import annotations

import numpy as np
from typing import Optional

from h11_cga.types import CGAConfig, NUM_DIMENSIONS

class DivergenceRatio:
    """
    DR - Divergence Ratio / Threat Magnitude Engine.
    
    Computes threat magnitudes and adjusted ratios based on divergence.
    """
    
    def __init__(self, config: CGAConfig):
        """
        Initialize the DivergenceRatio engine.
        
        Args:
            config: The CGA configuration object.
        """
        self.config = config
        self._dr_history: list[float] = []

    def compute_dr(self, divergence: np.ndarray, weights: np.ndarray | None = None, sigmas: np.ndarray | None = None) -> float:
        """
        Compute DR_c(t) = sqrt(sum(w_i * (divergence_i / sigma_i)^2)).
        
        Args:
            divergence: The divergence vector (X_c - X_c*).
            weights: Optional custom weights. Defaults to config.dr_weights.
            sigmas: Optional custom sigmas. Defaults to config.dr_sigmas.
            
        Returns:
            float: The computed Divergence Ratio.
        """
        if weights is None:
            weights = getattr(self.config, 'dr_weights', np.ones(NUM_DIMENSIONS))
        if sigmas is None:
            sigmas = getattr(self.config, 'dr_sigmas', np.ones(NUM_DIMENSIONS))
            
        # Add epsilon to sigmas to avoid division by zero
        sigmas_safe = np.maximum(sigmas, 1e-6)
        
        normalized_div = divergence / sigmas_safe
        dr_squared = np.sum(weights * (normalized_div ** 2))
        return float(np.sqrt(dr_squared))

    def compute_domain_adjusted_dr(self, dr: float, domain_metric: float) -> float:
        """
        Compute DR_c^(a) = W_c(a) * DR_c.
        
        Args:
            dr: The base Divergence Ratio.
            domain_metric: The domain adjustment weight/metric W_c(a).
            
        Returns:
            float: The adjusted Divergence Ratio.
        """
        return float(domain_metric * dr)

    def get_dr_rate(self, dt: float = 1.0) -> float:
        """
        Compute the finite difference of DR history (d/dt DR_c).

        Returns:
            float: The rate of change of DR.
        """
        if len(self._dr_history) < 2:
            return 0.0
        return (self._dr_history[-1] - self._dr_history[-2]) / max(dt, 1e-9)

    def record(self, dr_value: float) -> None:
        """
        Append a DR value to the rolling history.
        
        Args:
            dr_value: The DR value to record.
        """
        self._dr_history.append(dr_value)
        
        window_size = getattr(self.config, 'dsa_history_window', 100)
        if len(self._dr_history) > window_size:
            self._dr_history = self._dr_history[-window_size:]

    def reset(self) -> None:
        """
        Reset the engine history.
        """
        self._dr_history.clear()
