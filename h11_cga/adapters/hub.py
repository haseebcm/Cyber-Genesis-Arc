"""
H¹¹-CGA Telemetry Ingestion Hub
=================================

Multi-source Telemetry Aggregator managing all active adapters (VIE) and
feeding unified TelemetryInput payloads into the CyberGenesisEngine.
"""

from __future__ import annotations

import logging
import time
from typing import Dict, Any, List, Optional

import numpy as np

from h11_cga.adapters.base import BaseTelemetryAdapter
from h11_cga.types import (
    TelemetryInput,
    SecurityEvent,
    NUM_DIMENSIONS,
    DIMENSION_NAMES,
)

logger = logging.getLogger(__name__)


class TelemetryIngestionHub:
    """
    Telemetry Ingestion Hub.

    Manages multiple active BaseTelemetryAdapter instances, aggregates metrics
    from host OS, K8s, eBPF probes, and log streams, and merges them into a single
    normalized TelemetryInput for each cycle of CyberGenesisEngine.
    """

    def __init__(self) -> None:
        self._adapters: Dict[str, BaseTelemetryAdapter] = {}
        self._total_ticks: int = 0

    def register_adapter(self, adapter: BaseTelemetryAdapter) -> None:
        """Register a telemetry adapter."""
        self._adapters[adapter.name] = adapter
        adapter.start()
        logger.info(f"Registered adapter '{adapter.name}' with Ingestion Hub.")

    def unregister_adapter(self, name: str) -> Optional[BaseTelemetryAdapter]:
        """Unregister and stop a telemetry adapter."""
        if name in self._adapters:
            adapter = self._adapters.pop(name)
            adapter.stop()
            logger.info(f"Unregistered adapter '{name}' from Ingestion Hub.")
            return adapter
        return None

    def get_adapter(self, name: str) -> Optional[BaseTelemetryAdapter]:
        """Get an adapter by name."""
        return self._adapters.get(name)

    @property
    def registered_adapters(self) -> List[str]:
        """Return names of registered adapters."""
        return list(self._adapters.keys())

    def collect_all(self) -> TelemetryInput:
        """
        Collect telemetry from all registered active adapters, merge raw values
        and events, and produce a unified TelemetryInput.
        """
        now = time.time()
        merged_raw: Dict[str, float] = {}
        dimension_accumulators: Dict[str, List[float]] = {
            name.lower(): [] for name in DIMENSION_NAMES
        }
        all_events: List[SecurityEvent] = []

        for name, adapter in self._adapters.items():
            if not adapter.is_active():
                continue
            try:
                telemetry = adapter.collect()

                # Accumulate raw values per dimension
                for key, val in telemetry.raw_values.items():
                    key_lower = key.lower()
                    if key_lower in dimension_accumulators:
                        dimension_accumulators[key_lower].append(val)

                # Accumulate events
                all_events.extend(telemetry.events)

            except Exception as err:
                logger.error(f"Error collecting telemetry from adapter '{name}': {err}")

        # Average raw values across active adapters for each dimension
        for dim_name, val_list in dimension_accumulators.items():
            if val_list:
                merged_raw[dim_name] = float(np.mean(val_list))

        self._total_ticks += 1

        return TelemetryInput(
            raw_values=merged_raw,
            events=all_events,
            timestamp=now,
        )
