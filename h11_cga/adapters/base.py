"""
H¹¹-CGA Base Telemetry Adapter (VIE)
=====================================

Abstract Base Class for all telemetry adapters (Virtual Interface Engines).
Adapters translate real-world metrics, logs, and events into normalized
11-dimensional TelemetryInput objects for the CyberGenesisEngine.
"""

from __future__ import annotations

import abc
import logging
import time
from typing import Any, Dict, List, Optional

import numpy as np

from h11_cga.types import (
    TelemetryInput,
    SecurityEvent,
    NUM_DIMENSIONS,
    DIMENSION_NAMES,
    DIMENSION_INDEX,
)

logger = logging.getLogger(__name__)


class BaseTelemetryAdapter(abc.ABC):
    """
    Abstract Base Class for Telemetry Normalization Adapters.

    Subclasses implement ``collect()`` to sample real metrics or events from
    underlying systems (Host OS, K8s, eBPF probes, Log files) and map them
    to normalized values in [0, 1] for the 11 MCC security dimensions.
    """

    def __init__(self, name: str, polling_interval: float = 1.0) -> None:
        self.name = name
        self.polling_interval = polling_interval
        self._active = False
        self._last_sample_time = 0.0
        self._metrics_history: List[Dict[str, float]] = []

    @abc.abstractmethod
    def collect(self) -> TelemetryInput:
        """
        Collect and normalize telemetry from the target system.

        Returns:
            A TelemetryInput object containing normalized dimension values
            in raw_values and any detected SecurityEvents.
        """
        pass

    def start(self) -> None:
        """Start telemetry collection."""
        self._active = True
        logger.info(f"Started telemetry adapter: {self.name}")

    def stop(self) -> None:
        """Stop telemetry collection."""
        self._active = False
        logger.info(f"Stopped telemetry adapter: {self.name}")

    def is_active(self) -> bool:
        """Check if the adapter is actively collecting."""
        return self._active

    def scale_metric(
        self, value: float, min_val: float, max_val: float, invert: bool = False
    ) -> float:
        """
        Helper method to normalize a metric into [0.0, 1.0].

        Args:
            value: Raw metric value.
            min_val: Baseline/nominal minimum.
            max_val: Upper boundary threshold.
            invert: If True, higher raw metric = lower health (e.g. high CPU = low health).

        Returns:
            Normalized float in [0.0, 1.0] representing dimension integrity.
        """
        if max_val <= min_val:
            return 1.0
        clamped = max(min_val, min(max_val, value))
        norm = (clamped - min_val) / (max_val - min_val)
        if invert:
            norm = 1.0 - norm
        return float(np.clip(norm, 0.0, 1.0))
