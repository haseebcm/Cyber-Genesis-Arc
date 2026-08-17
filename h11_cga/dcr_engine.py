from __future__ import annotations

import logging
import numpy as np
import time

from h11_cga.types import (
    ActionUrgency,
    ResponseAction,
    ActionType,
    DivergenceResult,
    HSAZone,
    CGAConfig,
    DIMENSION_NAMES
)

logger = logging.getLogger(__name__)

class DCREngine:
    """Dynamic Cyber Response (ΔCR) Engine."""

    def __init__(self, config: CGAConfig):
        self.config = config
        self.thresholds = getattr(config, 'dcr_thresholds', [0.25, 0.50, 0.75])

    def compute_priority(self, pressure: float, switching_burden: float, normalization: float, slack: float) -> float:
        """Compute the ΔCR priority for a specific action or dimension.
        
        Formula: ΔCR_j = (PT_j + ST_j) * N_j - T_slack,j
        """
        return (pressure + switching_burden) * normalization - slack

    def classify_urgency(self, dcr: float) -> ActionUrgency:
        """Classify action urgency based on ΔCR score."""
        if dcr < self.thresholds[0]:
            return ActionUrgency.LOW
        elif dcr < self.thresholds[1]:
            return ActionUrgency.MEDIUM
        elif dcr < self.thresholds[2]:
            return ActionUrgency.HIGH
        else:
            return ActionUrgency.CRITICAL

    def recommend_action(self, dcr: float, dimension: int, divergence_magnitude: float) -> ResponseAction:
        """Recommend a response action based on urgency and dimension."""
        urgency = self.classify_urgency(dcr)
        dim_name = DIMENSION_NAMES[dimension] if 0 <= dimension < len(DIMENSION_NAMES) else f"DIM_{dimension}"
        
        # Determine action type based on urgency and dimension context
        if urgency == ActionUrgency.CRITICAL:
            if "identity" in dim_name.lower():
                action_type = ActionType.REVOKE
            elif "network" in dim_name.lower():
                action_type = ActionType.ISOLATE
            else:
                action_type = ActionType.EMERGENCY_SHUTDOWN
        elif urgency == ActionUrgency.HIGH:
            if "data" in dim_name.lower():
                action_type = ActionType.QUARANTINE
            elif "crypto" in dim_name.lower():
                action_type = ActionType.ROTATE
            else:
                action_type = ActionType.NULLIFY
        elif urgency == ActionUrgency.MEDIUM:
            action_type = ActionType.PREPARE
        else:
            action_type = ActionType.MONITOR

        return ResponseAction(
            action_type=action_type,
            target=dim_name,
            urgency=urgency,
            dcr_score=dcr,
            description=f"Automated response for {dim_name} due to divergence {divergence_magnitude:.3f}",
            dimension=dimension,
            timestamp=time.time()
        )

    def rank_actions(self, assessments: list[tuple[int, float, float]]) -> list[ResponseAction]:
        """Generate and rank response actions for multiple assessments.
        
        Args:
            assessments: list of (dimension, pressure, slack)
        """
        actions = []
        for dim, pressure, slack in assessments:
            switching_burden = 0.1
            normalization = 1.0
            dcr = self.compute_priority(pressure, switching_burden, normalization, slack)
            
            divergence_magnitude = pressure 
            action = self.recommend_action(dcr, dim, divergence_magnitude)
            actions.append(action)
            
        actions.sort(key=lambda x: x.dcr_score, reverse=True)
        return actions

    def generate_response_plan(self, divergence: DivergenceResult, hsa_zone: HSAZone, cci_subcritical: bool) -> list[ResponseAction]:
        """Generate a comprehensive response plan based on divergence and HSA context."""
        assessments = []
        for i, div_val in enumerate(divergence.divergence_vector):
            if abs(div_val) > 0.05:
                pressure = abs(div_val)
                slack = 0.1
                if hsa_zone == HSAZone.CRITICAL:
                    slack = 0.05
                elif hsa_zone == HSAZone.SINGULARITY:
                    slack = 0.0
                
                # Amplify when cascade is supercritical (CCI ≥ Θ_c), not when safe
                if not cci_subcritical:
                    pressure *= 1.5
                    
                assessments.append((i, pressure, slack))
                
        return self.rank_actions(assessments)
