"""
H¹¹-CGA Host System Telemetry Adapter
======================================

Real OS Metric Collector mapping host system performance (via psutil)
directly into the MCC Security State Vector dimensions it can observe.

Reports only dimensions measurable from the host OS. Authorization, Trust,
and Governance are behavioural/policy dimensions with no honest psutil
source, so they are left to event-driven adapters (e.g. LogAdapter) and to
cross-dimensional propagation through the transformation matrix.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Dict, Optional, Tuple

import numpy as np
import psutil

from h11_cga.adapters.base import BaseTelemetryAdapter
from h11_cga.types import (
    TelemetryInput,
    SecurityEvent,
    NUM_DIMENSIONS,
)

logger = logging.getLogger(__name__)


class SystemAdapter(BaseTelemetryAdapter):
    """
    Host System Telemetry Adapter using ``psutil``.

    Collects real OS metrics (CPU, RAM, swap, disk, sockets, processes,
    logins) and normalizes them into [0, 1] health values. Metrics that are
    unavailable this cycle — first-sample rates, or counters blocked by
    platform permissions — are omitted rather than substituted.
    """

    def __init__(self, polling_interval: float = 1.0) -> None:
        super().__init__(name="SystemHostAdapter", polling_interval=polling_interval)
        # Prime the CPU sampler so the first collect() returns a real delta
        # instead of psutil's meaningless 0.0 initial reading.
        psutil.cpu_percent(interval=None)
        self._disk_root = os.path.abspath(os.sep)
        self._network_readable = True

    @property
    def measured_dimensions(self) -> Tuple[str, ...]:
        return (
            "identity",
            "network",
            "data",
            "compute",
            "memory",
            "execution",
            "resource",
            "recovery",
        )

    def collect(self) -> TelemetryInput:
        """Collect host OS metrics and normalize the dimensions we can observe."""
        now = time.time()
        events = []

        # --- Compute ---
        cpu_percent = psutil.cpu_percent(interval=None)
        compute_health = self.scale_metric(cpu_percent, 0.0, 95.0, invert=True)

        # --- Memory ---
        mem = psutil.virtual_memory()
        memory_health = self.scale_metric(mem.percent, 0.0, 95.0, invert=True)

        if mem.percent > 90.0:
            events.append(
                SecurityEvent(
                    event_type="high_memory_pressure",
                    source=self.name,
                    target_dimensions=[5],
                    impact=np.array([0, 0, 0, 0, 0, -0.3, 0, 0, 0, 0, 0]),
                    severity=0.8,
                    metadata={"mem_percent": mem.percent},
                    timestamp=now,
                )
            )

        # --- Resource (disk capacity on the system root) ---
        resource_health: Optional[float]
        try:
            disk = psutil.disk_usage(self._disk_root)
            resource_health = self.scale_metric(disk.percent, 0.0, 95.0, invert=True)
        except OSError as err:
            logger.debug(f"{self.name}: disk usage unavailable: {err}")
            resource_health = None

        # --- Network (active inet sockets) ---
        network_health: Optional[float] = None
        if self._network_readable:
            try:
                net_conns = len(psutil.net_connections(kind="inet"))
                network_health = self.scale_metric(net_conns, 0.0, 500.0, invert=True)
            except (psutil.AccessDenied, PermissionError):
                # Requires elevation on some platforms; stop claiming this
                # dimension instead of reporting a fabricated value.
                self._network_readable = False
                logger.info(
                    f"{self.name}: socket enumeration denied; omitting 'network' dimension"
                )
            except Exception as err:
                logger.debug(f"{self.name}: socket enumeration failed: {err}")

        # --- Execution (process table + anomalous CPU consumers) ---
        procs = len(psutil.pids())
        execution_health = self.scale_metric(procs, 50.0, 600.0, invert=True)

        high_cpu_procs = 0
        try:
            for p in psutil.process_iter(["pid", "name", "cpu_percent"]):
                if (p.info.get("cpu_percent") or 0.0) > 80.0:
                    high_cpu_procs += 1
        except Exception as err:
            logger.debug(f"{self.name}: error scanning process cpu: {err}")

        if high_cpu_procs > 3:
            events.append(
                SecurityEvent(
                    event_type="anomalous_process_execution",
                    source=self.name,
                    target_dimensions=[6, 4],
                    impact=np.array([0, 0, 0, 0, -0.2, 0, -0.3, 0, 0, 0, 0]),
                    severity=0.7,
                    metadata={"high_cpu_count": high_cpu_procs},
                    timestamp=now,
                )
            )

        # --- Identity (concurrent interactive sessions) ---
        identity_health: Optional[float]
        try:
            users = len(psutil.users())
            identity_health = self.scale_metric(users, 0.0, 10.0, invert=True)
        except Exception as err:
            logger.debug(f"{self.name}: session enumeration failed: {err}")
            identity_health = None

        # --- Data (disk I/O throughput rate, not cumulative totals) ---
        data_health: Optional[float] = None
        try:
            disk_io = psutil.disk_io_counters()
        except Exception as err:
            logger.debug(f"{self.name}: disk io counters unavailable: {err}")
            disk_io = None

        if disk_io is not None:
            io_total = float(disk_io.read_bytes + disk_io.write_bytes)
            io_rate = self.compute_rate("disk_io_bytes", io_total, now)
            if io_rate is not None:
                # Saturate at 200 MB/s sustained throughput
                data_health = self.scale_metric(io_rate, 0.0, 2e8, invert=True)

        # --- Recovery (swap pressure) ---
        recovery_health: Optional[float]
        try:
            swap = psutil.swap_memory()
            recovery_health = self.scale_metric(swap.percent, 0.0, 80.0, invert=True)
        except Exception as err:
            logger.debug(f"{self.name}: swap metrics unavailable: {err}")
            recovery_health = None

        return self.build_telemetry(
            {
                "identity": identity_health,
                "network": network_health,
                "data": data_health,
                "compute": compute_health,
                "memory": memory_health,
                "execution": execution_health,
                "resource": resource_health,
                "recovery": recovery_health,
            },
            events=events,
            timestamp=now,
        )
