from __future__ import annotations

import time

import numpy as np

from h11_cga.types import (
    CGAConfig,
    SecurityState,
    SecurityBaseline,
    SecurityEvent,
    TelemetryInput,
    NUM_DIMENSIONS,
    DIMENSION_INDEX,
)


class SecurityStateSpace:
    """
    MCC - Security State Space Engine.

    Maintains the current 11-dimensional security state X_c(t), history,
    and baseline envelope Ω_c. Nominal is 1.0 (secure); 0.0 is failed.
    """

    def __init__(self, config: CGAConfig):
        self.config = config
        self._state_history: list[SecurityState] = []

        nominal = np.ones(NUM_DIMENSIONS)
        self.current_state = SecurityState(
            vector=nominal.copy(),
            timestamp=time.time(),
        )
        self.baseline = SecurityBaseline(
            reference=nominal.copy(),
            lower_bound=np.full(NUM_DIMENSIONS, 0.7),
            upper_bound=np.ones(NUM_DIMENSIONS),
        )

    def update_state(self, new_state: SecurityState) -> None:
        """Update the current state and append to the rolling history."""
        self.current_state = new_state
        self._state_history.append(new_state)

        window_size = getattr(self.config, "dsa_history_window", 100)
        if len(self._state_history) > window_size:
            self._state_history = self._state_history[-window_size:]

    def apply_event(self, event: SecurityEvent) -> SecurityState:
        """Apply event impact to the current state and return the new state."""
        new_vector = np.clip(self.current_state.vector + event.impact, 0.0, 1.0)
        new_state = SecurityState(
            vector=new_vector,
            timestamp=time.time(),
        )
        self.update_state(new_state)
        return new_state

    def apply_telemetry(self, telemetry: TelemetryInput) -> SecurityState:
        """Map raw telemetry into dimensions, accumulate events, clip once."""
        new_vector = self.current_state.vector.copy()

        for dim_name, val in telemetry.raw_values.items():
            dim_name_lower = dim_name.lower()
            if dim_name_lower in DIMENSION_INDEX:
                idx = DIMENSION_INDEX[dim_name_lower]
                new_vector[idx] = float(np.clip(val, 0.0, 1.0))

        for event in telemetry.events:
            new_vector = new_vector + event.impact

        new_vector = np.clip(new_vector, 0.0, 1.0)
        new_state = SecurityState(
            vector=new_vector,
            timestamp=telemetry.timestamp,
        )
        self.update_state(new_state)
        return new_state

    def get_state_vector(self) -> np.ndarray:
        """Return the current state vector."""
        return self.current_state.vector

    def is_within_envelope(self) -> bool:
        """Check if the current state is within the baseline envelope Ω_c."""
        return bool(self.baseline.is_within_envelope(self.current_state))

    def get_envelope_utilization(self) -> np.ndarray:
        """Per-dimension utilization of the allowable envelope."""
        return self.baseline.envelope_utilization(self.current_state)

    def update_baseline(self, new_reference: np.ndarray, tolerance: float = 0.3) -> None:
        """Set a new reference X_c* and recompute envelope bounds [L_c, U_c]."""
        reference = np.clip(np.asarray(new_reference, dtype=np.float64), 0.0, 1.0)
        lower = np.clip(reference - tolerance, 0.0, 1.0)
        upper = np.clip(reference + tolerance, 0.0, 1.0)
        self.baseline = SecurityBaseline(
            reference=reference.copy(),
            lower_bound=lower,
            upper_bound=upper,
        )

    def get_history(self) -> list[SecurityState]:
        """Return the rolling state history."""
        return self._state_history

    def reset(self) -> None:
        """Reset to the nominal secure state (all dimensions = 1.0)."""
        self._state_history.clear()
        nominal = np.ones(NUM_DIMENSIONS)
        self.current_state = SecurityState(
            vector=nominal.copy(),
            timestamp=time.time(),
        )
        self.baseline = SecurityBaseline(
            reference=nominal.copy(),
            lower_bound=np.full(NUM_DIMENSIONS, 0.7),
            upper_bound=np.ones(NUM_DIMENSIONS),
        )
