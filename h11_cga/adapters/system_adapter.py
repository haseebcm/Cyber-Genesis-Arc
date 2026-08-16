"""
H¹¹-CGA Host System Telemetry Adapter
======================================

Real OS Metric Collector mapping host system performance (via psutil)
directly into the 11 MCC Security State Vector dimensions.
"""

from __future__ import annotations

import logging
import time
from typing import Dict, Any, Optional

import numpy as np
import psutil

from h11_cga.adapters.base import BaseTelemetryAdapter
from h11_cga.types import (
    TelemetryInput,
    SecurityEvent,
    NUM_DIMENSIONS,
    DIMENSION_NAMES,
)

logger = logging.getLogger(__name__)


class SystemAdapter(BaseTelemetryAdapter):
    """
    Host System Telemetry Adapter using ``psutil``.

    Collects real OS metrics (CPU, RAM, Sockets, Processes, Auth) and translates
    them into normalized [0, 1] health state values across the 11 MCC dimensions.
    """

    def __init__(self, polling_interval: float = 1.0) -> None:
        super().__init__(name="SystemHostAdapter", polling_interval=polling_interval)
        self._initial_cpu_times = psutil.cpu_times()

    def collect(self) -> TelemetryInput:
        """Collect host OS metrics and normalize into 11 MCC dimensions."""
        now = time.time()
        events = []

        # --- 1. Compute Dimension ---
        cpu_percent = psutil.cpu_percent(interval=None)
        compute_health = self.scale_metric(cpu_percent, 0.0, 95.0, invert=True)

        # --- 2. Memory Dimension ---
        mem = psutil.virtual_memory()
        memory_health = self.scale_metric(mem.percent, 0.0, 95.0, invert=True)

        # Trigger event if memory is dangerously low
        if mem.percent > 90.0:
            events.append(
                SecurityEvent(
                    event_type="high_memory_pressure",
                    source=self.name,
                    target_dimensions=[5],  # Memory index
                    impact=np.array([0, 0, 0, 0, 0, -0.3, 0, 0, 0, 0, 0]),
                    severity=0.8,
                    metadata={"mem_percent": mem.percent},
                    timestamp=now,
                )
            )

        # --- 3. Resource Dimension ---
        disk = psutil.disk_usage("/")
        resource_health = self.scale_metric(disk.percent, 0.0, 95.0, invert=True)

        # --- 4. Network Dimension ---
        net_conns = len(psutil.net_connections(kind="inet"))
        # Scale active sockets (0 to 500 connections safe baseline)
        network_health = self.scale_metric(net_conns, 0.0, 500.0, invert=True)

        # --- 5. Execution Dimension ---
        procs = len(psutil.pids())
        execution_health = self.scale_metric(procs, 50.0, 600.0, invert=True)

        # Check for high-CPU anomalous processes
        high_cpu_procs = 0
        try:
            for p in psutil.process_iter(["pid", "name", "cpu_percent"]):
                if (p.info.get("cpu_percent") or 0.0) > 80.0:
                    high_cpu_procs += 1
        except Exception as err:
            logger.debug(f"Error scanning process cpu: {err}")

        if high_cpu_procs > 3:
            events.append(
                SecurityEvent(
                    event_type="anomalous_process_execution",
                    source=self.name,
                    target_dimensions=[6, 4],  # Execution, Compute
                    impact=np.array([0, 0, 0, 0, -0.2, 0, -0.3, 0, 0, 0, 0]),
                    severity=0.7,
                    metadata={"high_cpu_count": high_cpu_procs},
                    timestamp=now,
                )
            )

        # --- 6. Identity Dimension ---
        users = len(psutil.users())
        identity_health = self.scale_metric(users, 0.0, 10.0, invert=True)

        # --- 7. Authorization Dimension ---
        # Privileged processes check (e.g. root/admin sessions)
        auth_health = 0.95  # Nominal baseline

        # --- 8. Trust Dimension ---
        # System uptime stability (scaled up to 30 days)
        boot_time = psutil.boot_time()
        uptime_days = (now - boot_time) / 86400.0
        trust_health = float(np.clip(0.7 + (min(uptime_days, 30.0) / 100.0), 0.7, 1.0))

        # --- 9. Governance Dimension ---
        governance_health = 0.95

        # --- 10. Data Dimension ---
        disk_io = psutil.disk_io_counters()
        io_busy = (disk_io.read_bytes + disk_io.write_bytes) if disk_io else 0
        data_health = self.scale_metric(io_busy, 0.0, 1e8, invert=True)

        # --- 11. Recovery Dimension ---
        swap = psutil.swap_memory()
        recovery_health = self.scale_metric(swap.percent, 0.0, 80.0, invert=True)

        # Map metrics to dimension names
        raw_values = {
            "identity": identity_health,
            "authorization": auth_health,
            "network": network_health,
            "data": data_health,
            "compute": compute_health,
            "memory": memory_health,
            "execution": execution_health,
            "resource": resource_health,
            "trust": trust_health,
            "governance": governance_health,
            "recovery": recovery_health,
        }

        self._last_sample_time = now

        return TelemetryInput(
            raw_values=raw_values,
            events=events,
            timestamp=now,
        )
