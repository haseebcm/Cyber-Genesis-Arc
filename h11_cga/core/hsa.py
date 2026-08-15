from __future__ import annotations

from typing import Optional
from h11_cga.types import CGAConfig, HSAZone

class SingularityTracker:
    """
    HSA - Hyper-Singularity Approach Engine.
    
    Tracks singularity coordinates and manages the security buffer.
    """
    
    def __init__(self, config: CGAConfig):
        """
        Initialize the SingularityTracker.
        
        Args:
            config: The CGA configuration object.
        """
        self.config = config
        self._security_buffer: float = getattr(config, 'initial_security_buffer', 1.0)
        self._hsa_history: list[float] = []

    def compute_singularity_coordinate(self, dr: float, security_buffer: float | None = None) -> float:
        """
        Compute H_c(t) = k * DR_c(t) - B_c(t).
        
        Args:
            dr: The Divergence Ratio DR_c(t).
            security_buffer: Optional override for the security buffer B_c(t).
            
        Returns:
            float: The singularity coordinate H_c(t).
        """
        k = getattr(self.config, 'hsa_amplification', 1.0)
        b_c = security_buffer if security_buffer is not None else self._security_buffer
        
        hc = (k * dr) - b_c
        self._hsa_history.append(hc)
        
        window_size = getattr(self.config, 'dsa_history_window', 100)
        if len(self._hsa_history) > window_size:
            self._hsa_history = self._hsa_history[-window_size:]
            
        return hc

    def get_zone(self, hc: float) -> HSAZone:
        """
        Determine the HSA zone based on the coordinate.
        
        Args:
            hc: The singularity coordinate H_c(t).
            
        Returns:
            HSAZone: CONTROLLED, CRITICAL, or SINGULARITY.
        """
        threshold = getattr(self.config, 'hsa_critical_threshold', 0.5)
        
        if hc < -threshold:
            return HSAZone.CONTROLLED
        elif hc > threshold:
            return HSAZone.SINGULARITY
        else:
            return HSAZone.CRITICAL

    def update_buffer(self, dr: float, dt: float = 1.0) -> float:
        """
        Update the security buffer B_c(t).
        
        Args:
            dr: The Divergence Ratio DR_c(t).
            dt: Time delta.
            
        Returns:
            float: The updated security buffer.
        """
        initial_buffer = getattr(self.config, 'initial_security_buffer', 1.0)
        decay_rate = getattr(self.config, 'buffer_decay_rate', 0.1)
        recovery_rate = getattr(self.config, 'buffer_recovery_rate', 0.05)
        
        if dr > 0.1:
            self._security_buffer -= decay_rate * dt
        else:
            self._security_buffer += recovery_rate * dt
            
        # Clamp between 0 and initial_buffer
        self._security_buffer = max(0.0, min(self._security_buffer, initial_buffer))
        return self._security_buffer

    def estimate_time_to_boundary(self) -> float | None:
        """
        Estimate time to singularity boundary via linear extrapolation.
        
        Returns:
            float | None: Time to boundary, or None if not approaching.
        """
        if len(self._hsa_history) < 2:
            return None
            
        current_hc = self._hsa_history[-1]
        prev_hc = self._hsa_history[-2]
        
        rate = current_hc - prev_hc
        if rate <= 1e-6:
            return None
            
        threshold = getattr(self.config, 'hsa_critical_threshold', 0.5)
        if current_hc >= threshold:
            return 0.0
            
        return (threshold - current_hc) / rate

    def get_security_buffer(self) -> float:
        """
        Get the current security buffer value.
        
        Returns:
            float: Current B_c(t).
        """
        return self._security_buffer

    def reset(self) -> None:
        """
        Reset the engine history and buffer.
        """
        self._security_buffer = getattr(self.config, 'initial_security_buffer', 1.0)
        self._hsa_history.clear()
