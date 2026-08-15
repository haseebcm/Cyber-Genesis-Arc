from __future__ import annotations

import time
import numpy as np
from typing import List, Optional

from h11_cga.types import (
    CGAConfig,
    SecurityState,
    SecurityBaseline,
    SecurityEvent,
    TelemetryInput,
    NUM_DIMENSIONS,
    DIMENSION_INDEX
)

class SecurityStateSpace:
    """
    MCC - Security State Space Engine.
    
    Maintains the current security state, history, and baseline.
    """
    
    def __init__(self, config: CGAConfig):
        """
        Initialize the SecurityStateSpace.
        
        Args:
            config: The CGA configuration object.
        """
        self.config = config
        self._state_history: list[SecurityState] = []
        
        # Initialize default state and baseline
        default_vector = np.zeros(NUM_DIMENSIONS)
        self.current_state = SecurityState(
            vector=default_vector.copy(),
            timestamp=time.time()
        )
        
        self.baseline = SecurityBaseline(
            reference=default_vector.copy(),
            lower_bound=np.zeros(NUM_DIMENSIONS),
            upper_bound=np.ones(NUM_DIMENSIONS)
        )

    def update_state(self, new_state: SecurityState) -> None:
        """
        Update the current state and append to history.
        
        Args:
            new_state: The new SecurityState.
        """
        self.current_state = new_state
        self._state_history.append(new_state)
        
        # Bound history by config.dsa_history_window
        window_size = getattr(self.config, 'dsa_history_window', 100)
        if len(self._state_history) > window_size:
            self._state_history = self._state_history[-window_size:]

    def apply_event(self, event: SecurityEvent) -> SecurityState:
        """
        Apply event impacts to the current state, returning the new state.
        
        Args:
            event: The SecurityEvent to apply.
            
        Returns:
            The newly computed SecurityState.
        """
        new_vector = self.current_state.vector + event.impact
        new_vector = np.clip(new_vector, 0.0, 1.0)
        
        new_state = SecurityState(
            vector=new_vector,
            timestamp=time.time(),
            dimension_dict={}
        )
        self.update_state(new_state)
        return new_state

    def apply_telemetry(self, telemetry: TelemetryInput) -> SecurityState:
        """
        Normalize raw telemetry values into state dimensions and apply events.
        
        Args:
            telemetry: The TelemetryInput to apply.
            
        Returns:
            The updated SecurityState.
        """
        new_vector = self.current_state.vector.copy()
        
        # Apply raw values mapped by dimension names
        for dim_name, val in telemetry.raw_values.items():
            dim_name_lower = dim_name.lower()
            if dim_name_lower in DIMENSION_INDEX:
                idx = DIMENSION_INDEX[dim_name_lower]
                # Assuming raw values need to be clamped [0, 1]
                new_vector[idx] = float(np.clip(val, 0.0, 1.0))
                
        new_state = SecurityState(
            vector=new_vector,
            timestamp=telemetry.timestamp,
            dimension_dict={}
        )
        self.update_state(new_state)
        
        # Apply events
        for event in telemetry.events:
            self.apply_event(event)
            
        return self.current_state

    def get_state_vector(self) -> np.ndarray:
        """
        Return the current state vector.
        
        Returns:
            np.ndarray: The current state vector.
        """
        return self.current_state.vector

    def is_within_envelope(self) -> bool:
        """
        Check if the current state is within the baseline envelope.
        
        Returns:
            bool: True if within envelope, False otherwise.
        """
        return bool(self.baseline.is_within_envelope(self.current_state.vector))

    def get_envelope_utilization(self) -> np.ndarray:
        """
        Calculate per-dimension utilization of the envelope.
        
        Returns:
            np.ndarray: The utilization per dimension.
        """
        return self.baseline.envelope_utilization(self.current_state.vector)

    def update_baseline(self, new_reference: np.ndarray, tolerance: float = 0.3) -> None:
        """
        Set a new reference and auto-compute its envelope bounds.
        
        Args:
            new_reference: The new reference vector.
            tolerance: The tolerance used to compute upper and lower bounds.
        """
        lower = np.clip(new_reference - tolerance, 0.0, 1.0)
        upper = np.clip(new_reference + tolerance, 0.0, 1.0)
        self.baseline = SecurityBaseline(
            reference=new_reference.copy(),
            lower_bound=lower,
            upper_bound=upper
        )

    def get_history(self) -> list[SecurityState]:
        """
        Return the state history.
        
        Returns:
            list[SecurityState]: The state history.
        """
        return self._state_history

    def reset(self) -> None:
        """
        Reset the engine to its nominal default state.
        """
        self._state_history.clear()
        default_vector = np.zeros(NUM_DIMENSIONS)
        self.current_state = SecurityState(
            vector=default_vector.copy(),
            timestamp=time.time()
        )
        self.baseline = SecurityBaseline(
            reference=default_vector.copy(),
            lower_bound=np.zeros(NUM_DIMENSIONS),
            upper_bound=np.ones(NUM_DIMENSIONS)
        )
