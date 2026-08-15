from __future__ import annotations
import logging
from h11_cga.types import CGAConfig, SystemStatus

logger = logging.getLogger(__name__)

class CyberGenesisEquation:
    """
    Evaluates the master Cyber Genesis Equation, mathematically bounding 
    the system safety state into a single output score.
    """
    def __init__(self, config: CGAConfig):
        self.config = config

    def compute(self, permission: float, dr_adjusted: float, dr_rate: float, hsa_positive: float, cci: float) -> float:
        """
        Computes G_c(t) = Π_c(t) * [1 - α*DR_c^(a) - β*|DR_dot_c^(a)| - γ*H_c+ - δ*(CCI_c/Θ_c)]
        """
        gc, _ = self.compute_with_breakdown(permission, dr_adjusted, dr_rate, hsa_positive, cci)
        return gc

    def compute_with_breakdown(self, permission: float, dr_adjusted: float, dr_rate: float, hsa_positive: float, cci: float) -> tuple[float, dict[str, float]]:
        """
        Evaluates the equation and provides all constituent factors for explainability.
        """
        c = self.config
        
        dr_term = c.alpha * dr_adjusted
        dr_rate_term = c.beta * abs(dr_rate)
        hsa_term = c.gamma * hsa_positive
        cci_ratio = cci / c.cci_threshold if c.cci_threshold > 0 else 0.0
        cci_term = c.delta * cci_ratio
        
        inner_sum = 1.0 - dr_term - dr_rate_term - hsa_term - cci_term
        raw_gc = permission * inner_sum
        
        # Clamp mathematically to real valid range
        gc = max(-1.0, min(1.0, raw_gc))
        
        breakdown = {
            "permission": float(permission),
            "dr_term": float(dr_term),
            "dr_rate_term": float(dr_rate_term),
            "hsa_term": float(hsa_term),
            "cci_term": float(cci_term),
            "inner_sum": float(inner_sum),
            "raw_gc": float(raw_gc),
            "gc": float(gc)
        }
        
        return gc, breakdown

    def classify_status(self, gc: float, permission: float) -> SystemStatus:
        """
        Translates the continuous Genesis coefficient into a discrete operational status.
        """
        if permission == 0.0:
            return SystemStatus.EMERGENCY
            
        t = self.config.status_thresholds
        
        if gc >= t.get('permitted', 0.8):
            return SystemStatus.PERMITTED
        elif gc >= t.get('monitoring', 0.5):
            return SystemStatus.MONITORING
        elif gc >= t.get('warning', 0.2):
            return SystemStatus.WARNING
        elif gc >= t.get('critical', 0.0):
            return SystemStatus.CRITICAL
        elif gc >= t.get('containment', -0.5):
            return SystemStatus.CONTAINMENT
        else:
            return SystemStatus.EMERGENCY

    def get_safety_conditions(self, permission: float, hsa: float, cci: float, dr_adjusted: float) -> dict[str, bool]:
        """
        Validates safety constraint boundaries according to architecture definitions.
        """
        return {
            "permission_granted": permission == 1.0,
            "hsa_negative": hsa < 0.0,
            "cci_subcritical": cci < self.config.cci_threshold,
            "dr_approaching_zero": dr_adjusted < 0.05
        }
