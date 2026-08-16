"""
H¹¹-CGA eBPF Network Probe Adapter
====================================

High-speed Linux eBPF network probe adapter for socket flow monitoring,
SYN flood tracking, port scan detection, and egress anomaly normalization.
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


class EBPFNetworkProbe(BaseTelemetryAdapter):
    """
    eBPF Network Probe Adapter.

    Simulates or interfaces with eBPF kernel probes (XDP/tc/kprobes) to capture
    low-level network socket traffic, SYN flood ratios, port scans, and unauthorized egress.
    """

    def __init__(self, polling_interval: float = 0.5) -> None:
        super().__init__(name="eBPFNetworkProbe", polling_interval=polling_interval)
        self._syn_flood_count: int = 0
        self._egress_violations: int = 0

    def sample_network_probe(
        self,
        pps: float = 1000.0,
        syn_ratio: float = 0.02,
        unauthorized_egress_attempts: int = 0,
        port_scan_signals: int = 0,
    ) -> TelemetryInput:
        """
        Sample or simulate eBPF kernel network metrics.

        Args:
            pps: Packets per second across network interfaces.
            syn_ratio: Ratio of TCP SYN packets to total packets.
            unauthorized_egress_attempts: Attempts to connect to blocked external IPs.
            port_scan_signals: Distinct target port connection bursts.
        """
        now = time.time()
        events = []

        # --- Network Dimension Health ---
        # Extreme SYN ratio (> 0.4) indicates SYN flood DDoS
        syn_health = self.scale_metric(syn_ratio * 100.0, 0.0, 40.0, invert=True)
        pps_health = self.scale_metric(pps, 0.0, 50000.0, invert=True)
        network_health = min(syn_health, pps_health)

        # Trigger network DDoS event
        if syn_ratio > 0.3 or pps > 30000.0:
            events.append(
                SecurityEvent(
                    event_type="ebpf_ddos_syn_flood",
                    source=self.name,
                    target_dimensions=[2, 7],  # Network, Resource
                    impact=np.array([0, 0, -0.6, 0, 0, 0, 0, -0.4, 0, 0, 0]),
                    severity=0.9,
                    metadata={"pps": pps, "syn_ratio": syn_ratio},
                    timestamp=now,
                )
            )

        # --- Egress & Port Scan Anomaly ---
        auth_health = self.scale_metric(unauthorized_egress_attempts, 0.0, 10.0, invert=True)
        execution_health = self.scale_metric(port_scan_signals, 0.0, 20.0, invert=True)

        if unauthorized_egress_attempts > 3:
            events.append(
                SecurityEvent(
                    event_type="ebpf_unauthorized_egress",
                    source=self.name,
                    target_dimensions=[2, 1],  # Network, Authorization
                    impact=np.array([0, -0.3, -0.4, 0, 0, 0, 0, 0, 0, 0, 0]),
                    severity=0.75,
                    metadata={"egress_attempts": unauthorized_egress_attempts},
                    timestamp=now,
                )
            )

        raw_values = {
            "identity": 0.95,
            "authorization": auth_health,
            "network": network_health,
            "data": 0.95,
            "compute": 0.95,
            "memory": 0.95,
            "execution": execution_health,
            "resource": pps_health,
            "trust": min(auth_health, network_health),
            "governance": 0.95,
            "recovery": 0.95,
        }

        return TelemetryInput(
            raw_values=raw_values,
            events=events,
            timestamp=now,
        )

    def collect(self) -> TelemetryInput:
        """Collect eBPF telemetry."""
        return self.sample_network_probe()
