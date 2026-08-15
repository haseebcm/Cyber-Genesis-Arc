from __future__ import annotations

import time
import numpy as np
from typing import List

from h11_cga.types import (
    CGAConfig,
    SecurityState,
    SecurityBaseline,
    DivergenceResult,
    DivergenceClassification,
    NUM_DIMENSIONS
)

class DirectionalDivergence:
    """
    DSA - Directional Security Divergence Engine.
    
    Computes and tracks divergence from baseline security states.
    """
    
    def __init__(self, config: CGAConfig):
        """
        Initialize the DirectionalDivergence engine.
        
        Args:
            config: The CGA configuration object.
        """
        self.config = config
        self._divergence_history: list[np.ndarray] = []

    def compute_divergence(self, current: SecurityState, baseline: SecurityBaseline) -> DivergenceResult:
        """
        Compute divergence D_c(t) = X_c(t) - X_c*.
        
        Calculates acceleration from history, classifies the divergence state,
        and stores the result in history.
        
        Args:
            current: The current security state.
            baseline: The reference security baseline.
            
        Returns:
            DivergenceResult: The computed divergence result.
        """
        divergence_vector = current.vector - baseline.reference
        magnitude = self.get_divergence_magnitude(divergence_vector)
        
        acceleration_vector = self.get_acceleration()
        acceleration_magnitude = float(np.linalg.norm(acceleration_vector))
        
        # Calculate finite difference for directional magnitude (d/dt of magnitude)
        if len(self._divergence_history) > 0:
            prev_magnitude = self.get_divergence_magnitude(self._divergence_history[-1])
            mag_derivative = magnitude - prev_magnitude
        else:
            mag_derivative = 0.0
            
        classification = self.classify(magnitude, mag_derivative)
        
        self._divergence_history.append(divergence_vector)
        
        window_size = getattr(self.config, 'dsa_history_window', 100)
        if len(self._divergence_history) > window_size:
            self._divergence_history = self._divergence_history[-window_size:]
            
        return DivergenceResult(
            divergence_vector=divergence_vector,
            acceleration_vector=acceleration_vector,
            magnitude=magnitude,
            acceleration_magnitude=acceleration_magnitude,
            classification=classification,
            timestamp=time.time()
        )

    def get_divergence_magnitude(self, divergence: np.ndarray) -> float:
        """
        Compute the L2 norm of the divergence vector.
        
        Args:
            divergence: The divergence vector.
            
        Returns:
            float: The L2 norm (magnitude).
        """
        return float(np.linalg.norm(divergence))

    def get_acceleration(self) -> np.ndarray:
        """
        Compute finite difference from the last two history entries.
        
        Returns:
            np.ndarray: The acceleration vector.
        """
        if len(self._divergence_history) < 2:
            return np.zeros(NUM_DIMENSIONS)
        
        return self._divergence_history[-1] - self._divergence_history[-2]

    def classify(self, magnitude: float, accel_magnitude: float) -> DivergenceClassification:
        """
        Classify the divergence state.
        
        Args:
            magnitude: The divergence magnitude.
            accel_magnitude: The derivative of magnitude (acceleration/velocity).
            
        Returns:
            DivergenceClassification: NORMAL, RECOVERING, or ESCALATING.
        """
        if magnitude < 0.05:
            return DivergenceClassification.NORMAL
        elif accel_magnitude < 0:
            return DivergenceClassification.RECOVERING
        else:
            return DivergenceClassification.ESCALATING

    def reset(self) -> None:
        """
        Reset the engine history.
        """
        self._divergence_history.clear()
