"""
H¹¹-CGA Telemetry Ingestion Hub
=================================

Multi-source Telemetry Aggregator managing all active adapters (VIE) and
feeding unified TelemetryInput payloads into the CyberGenesisEngine.

Only adapters whose real data source is reachable contribute, and each
dimension is averaged across the adapters that actually measured it. A
dimension no adapter observed is omitted, leaving its prior MCC value
untouched rather than overwriting it with a synthetic reading.
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

    Manages multiple BaseTelemetryAdapter instances, aggregates metrics from
    host OS, K8s, kernel network probes, and log streams, and merges them
    into a single normalized TelemetryInput for each engine cycle.
    """

    def __init__(self) -> None:
        self._adapters: Dict[str, BaseTelemetryAdapter] = {}
        self._total_ticks: int = 0
        self._last_provenance: Dict[str, List[str]] = {}
        self._last_skipped: Dict[str, str] = {}

    def register_adapter(self, adapter: BaseTelemetryAdapter) -> None:
        """Register a telemetry adapter."""
        self._adapters[adapter.name] = adapter
        adapter.start()
        if adapter.is_available():
            logger.info(f"Registered adapter '{adapter.name}' with Ingestion Hub.")
        else:
            logger.warning(
                f"Registered adapter '{adapter.name}' but its source is unavailable: "
                f"{adapter.unavailable_reason()}"
            )

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

    @property
    def measuring_adapters(self) -> List[str]:
        """Names of adapters that are active and have a reachable source."""
        return [
            name
            for name, adapter in self._adapters.items()
            if adapter.is_active() and adapter.is_available()
        ]

    @property
    def last_provenance(self) -> Dict[str, List[str]]:
        """Which adapters contributed each dimension on the last collection."""
        return {dim: list(sources) for dim, sources in self._last_provenance.items()}

    @property
    def last_skipped(self) -> Dict[str, str]:
        """Adapters skipped on the last collection, mapped to the reason."""
        return dict(self._last_skipped)

    def describe_sources(self) -> List[str]:
        """Human-readable status line per registered adapter."""
        lines = []
        for name, adapter in self._adapters.items():
            if not adapter.is_available():
                lines.append(f"{name}: SKIPPED — {adapter.unavailable_reason()}")
            elif not adapter.is_active():
                lines.append(f"{name}: STOPPED")
            else:
                dims = ", ".join(adapter.measured_dimensions) or "events only"
                lines.append(f"{name}: MEASURING [{dims}]")
        return lines

    def collect_all(self) -> TelemetryInput:
        """
        Collect telemetry from every reachable adapter, averaging each
        dimension over only those adapters that measured it.
        """
        now = time.time()
        merged_raw: Dict[str, float] = {}
        dimension_accumulators: Dict[str, List[float]] = {}
        provenance: Dict[str, List[str]] = {}
        skipped: Dict[str, str] = {}
        all_events: List[SecurityEvent] = []

        for name, adapter in self._adapters.items():
            if not adapter.is_active():
                skipped[name] = "adapter stopped"
                continue
            if not adapter.is_available():
                skipped[name] = adapter.unavailable_reason() or "source unavailable"
                continue

            try:
                telemetry = adapter.collect()
            except Exception as err:
                logger.error(f"Error collecting telemetry from adapter '{name}': {err}")
                skipped[name] = f"collection error: {err}"
                continue

            for key, val in telemetry.raw_values.items():
                key_lower = key.lower()
                dimension_accumulators.setdefault(key_lower, []).append(val)
                provenance.setdefault(key_lower, []).append(name)

            all_events.extend(telemetry.events)

        for dim_name, val_list in dimension_accumulators.items():
            if val_list:
                merged_raw[dim_name] = float(np.mean(val_list))

        self._total_ticks += 1
        self._last_provenance = provenance
        self._last_skipped = skipped

        return TelemetryInput(
            raw_values=merged_raw,
            events=all_events,
            timestamp=now,
        )
