"""
H¹¹-CGA Base Telemetry Adapter (VIE)
=====================================

Abstract Base Class for all telemetry adapters (Virtual Interface Engines).
Adapters translate real-world metrics, logs, and events into normalized
11-dimensional TelemetryInput objects for the CyberGenesisEngine.

Measurement contract
--------------------
An adapter reports a dimension ONLY if it genuinely measures it. Dimensions
outside ``measured_dimensions`` are omitted rather than padded with nominal
constants, because the ingestion hub averages across adapters and synthetic
values would dilute real signal. An adapter whose data source is unreachable
reports ``is_available() == False`` and is skipped entirely.
"""

from __future__ import annotations

import abc
import logging
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

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
    to normalized values in [0, 1] for the MCC security dimensions they
    actually observe.
    """

    def __init__(self, name: str, polling_interval: float = 1.0) -> None:
        self.name = name
        self.polling_interval = polling_interval
        self._active = False
        self._last_sample_time = 0.0
        self._metrics_history: List[Dict[str, float]] = []
        self._counter_state: Dict[str, Tuple[float, float]] = {}

    @abc.abstractmethod
    def collect(self) -> TelemetryInput:
        """
        Collect and normalize telemetry from the target system.

        Returns:
            A TelemetryInput containing normalized values for the dimensions
            this adapter measures, plus any detected SecurityEvents.
        """
        pass

    @property
    def measured_dimensions(self) -> Tuple[str, ...]:
        """
        Dimension names this adapter genuinely measures.

        Values reported for any other dimension are dropped by
        ``build_telemetry`` so unmeasured dimensions never enter the state.
        """
        return ()

    def is_available(self) -> bool:
        """Whether this adapter's real data source is reachable on this host."""
        return True

    def unavailable_reason(self) -> str:
        """Human-readable explanation when ``is_available()`` is False."""
        return ""

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

    def build_telemetry(
        self,
        measured: Dict[str, Optional[float]],
        events: Optional[Iterable[SecurityEvent]] = None,
        timestamp: Optional[float] = None,
    ) -> TelemetryInput:
        """
        Assemble a TelemetryInput from measured values only.

        Entries that are ``None`` (metric unavailable this cycle) or outside
        ``measured_dimensions`` are dropped rather than substituted.
        """
        ts = timestamp if timestamp is not None else time.time()
        allowed = {d.lower() for d in self.measured_dimensions}

        raw_values: Dict[str, float] = {}
        for key, value in measured.items():
            dim = key.lower()
            if value is None:
                continue
            if dim not in allowed:
                logger.debug(
                    f"{self.name}: dropping '{dim}' — not in measured_dimensions"
                )
                continue
            if dim not in DIMENSION_INDEX:
                continue
            raw_values[dim] = float(np.clip(value, 0.0, 1.0))

        self._last_sample_time = ts
        return TelemetryInput(
            raw_values=raw_values,
            events=list(events) if events else [],
            timestamp=ts,
        )

    def compute_rate(
        self, key: str, cumulative_total: float, now: Optional[float] = None
    ) -> Optional[float]:
        """
        Convert a monotonically increasing counter into a per-second rate.

        Returns None on the first sample or after a counter reset, since no
        honest rate can be derived yet.
        """
        ts = now if now is not None else time.time()
        previous = self._counter_state.get(key)
        self._counter_state[key] = (ts, float(cumulative_total))

        if previous is None:
            return None

        prev_ts, prev_total = previous
        elapsed = ts - prev_ts
        if elapsed <= 0:
            return None

        delta = float(cumulative_total) - prev_total
        if delta < 0:
            return None

        return delta / elapsed

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
