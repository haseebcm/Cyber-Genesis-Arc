from __future__ import annotations

import numpy as np
from typing import Optional, List

from h11_cga.types import CGAConfig, NUM_DIMENSIONS

class LimitEngine:
    """
    ULE - Universal Limit Engine.
    
    Manages multidimensional capacities and structural limit utilization.
    """
    
    def __init__(self, config: CGAConfig):
        """
        Initialize the LimitEngine.
        
        Args:
            config: The CGA configuration object.
        """
        self.config = config
        self._capacity: np.ndarray = getattr(
            config, 'ule_capacity', np.ones(NUM_DIMENSIONS)
        ).copy()

    def compute_limit_utilization(self, demand: np.ndarray, capacity: np.ndarray | None = None) -> float:
        """
        Compute overall structural limit utilization Ω_s = ||demand|| / ||capacity||.
        
        Args:
            demand: The current resource or security demand vector.
            capacity: Optional override for capacity. Defaults to self._capacity.
            
        Returns:
            float: The aggregate utilization ratio Ω_s.
        """
        cap = capacity if capacity is not None else self._capacity
        
        demand_norm = float(np.linalg.norm(demand))
        cap_norm = float(np.linalg.norm(cap))
        
        if cap_norm < 1e-6:
            return float('inf') if demand_norm > 0 else 0.0
            
        return demand_norm / cap_norm

    def compute_per_dimension_utilization(self, demand: np.ndarray, capacity: np.ndarray | None = None) -> np.ndarray:
        """
        Compute per-dimension utilization (demand / capacity).
        
        Args:
            demand: The demand vector.
            capacity: Optional capacity override.
            
        Returns:
            np.ndarray: Vector of per-dimension utilization ratios.
        """
        cap = capacity if capacity is not None else self._capacity
        cap_safe = np.maximum(cap, 1e-6)
        return demand / cap_safe

    def is_within_limit(self, utilization: float) -> bool:
        """
        Check if the utilization is strictly within limits (Ω_s < 1).
        
        Args:
            utilization: The computed utilization ratio.
            
        Returns:
            bool: True if utilization < 1.0, False otherwise.
        """
        return utilization < 1.0

    def get_remaining_buffer(self, utilization: float) -> float:
        """
        Calculate remaining buffer 1 - Ω_s clamped to >= 0.
        
        Args:
            utilization: The computed utilization ratio.
            
        Returns:
            float: The remaining buffer capacity.
        """
        return max(0.0, 1.0 - utilization)

    def adapt_capacity(self, history: list[float], growth_factor: float = 0.01) -> None:
        """
        Adjust capacity slightly based on sustained demand patterns.
        
        Args:
            history: List of historical aggregate utilization values.
            growth_factor: The rate at which capacity adjusts.
        """
        if not history:
            return
            
        avg_utilization = sum(history) / len(history)
        
        if avg_utilization > 0.8:
            # Increase capacity if demand is high
            self._capacity *= (1.0 + growth_factor)
        elif avg_utilization < 0.2:
            # Slowly decrease capacity if demand is consistently low
            self._capacity *= (1.0 - (growth_factor / 2))

    def reset(self) -> None:
        """
        Reset capacity back to config default.
        """
        self._capacity = getattr(
            self.config, 'ule_capacity', np.ones(NUM_DIMENSIONS)
        ).copy()
