"""
H¹¹-CGA Kernel Network Probe Adapter
=====================================

Linux network probe reading kernel TCP/IP counters for connection-attempt
rates, SYN-backlog drops, and packet throughput, normalized into the Network
and Resource MCC dimensions.

Measurement source
------------------
This adapter reads ``/proc/net/snmp`` and ``/proc/net/netstat`` (the same
counters ``netstat -s`` reports) plus per-NIC packet counters via psutil.
It does NOT currently load an eBPF/XDP program; attaching a real kernel
probe for per-flow SYN accounting is future work. On hosts without procfs
network counters (non-Linux), ``is_available()`` returns False and the
ingestion hub skips this adapter rather than contributing synthetic values.
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

_PROC_SNMP = "/proc/net/snmp"
_PROC_NETSTAT = "/proc/net/netstat"


class EBPFNetworkProbe(BaseTelemetryAdapter):
    """
    Kernel Network Probe Adapter.

    Derives Network health from real kernel counters: SYN-backlog drops
    (``ListenDrops``, ``ListenOverflows``, ``SyncookiesSent``) and packet
    throughput rates. ``sample_network_probe`` remains available as an
    explicit simulation entry point for demos and tests.
    """

    def __init__(self, polling_interval: float = 0.5) -> None:
        super().__init__(name="eBPFNetworkProbe", polling_interval=polling_interval)
        self._syn_flood_count: int = 0
        self._egress_violations: int = 0

    @property
    def measured_dimensions(self) -> Tuple[str, ...]:
        return ("network", "authorization", "execution", "resource")

    def is_available(self) -> bool:
        """True only when kernel network counters are readable on this host."""
        return os.path.exists(_PROC_SNMP) and os.access(_PROC_SNMP, os.R_OK)

    def unavailable_reason(self) -> str:
        if self.is_available():
            return ""
        return f"{_PROC_SNMP} not readable (kernel network counters require Linux)"

    # ------------------------------------------------------------------
    # Real kernel measurement
    # ------------------------------------------------------------------

    def _read_proc_counters(self, path: str) -> Dict[str, Dict[str, int]]:
        """
        Parse a procfs counter file into {protocol: {counter: value}}.

        Both /proc/net/snmp and /proc/net/netstat alternate a header line of
        counter names with a value line, keyed by protocol prefix.
        """
        tables: Dict[str, Dict[str, int]] = {}
        try:
            with open(path, "r", encoding="utf-8") as handle:
                lines = handle.read().splitlines()
        except OSError as err:
            logger.debug(f"{self.name}: cannot read {path}: {err}")
            return tables

        for i in range(0, len(lines) - 1, 2):
            header = lines[i].split()
            values = lines[i + 1].split()
            if not header or not values or header[0] != values[0]:
                continue
            protocol = header[0].rstrip(":")
            table: Dict[str, int] = {}
            for name, raw in zip(header[1:], values[1:]):
                try:
                    table[name] = int(raw)
                except ValueError:
                    continue
            tables[protocol] = table
        return tables

    def collect(self) -> TelemetryInput:
        """Collect real kernel network counters and normalize them."""
        now = time.time()

        if not self.is_available():
            return self.build_telemetry({}, events=[], timestamp=now)

        snmp = self._read_proc_counters(_PROC_SNMP)
        netstat = self._read_proc_counters(_PROC_NETSTAT)
        tcp = snmp.get("Tcp", {})
        tcp_ext = netstat.get("TcpExt", {})

        # SYN-backlog pressure: the kernel's own record of dropped or
        # cookie-deferred connection attempts.
        backlog_total = float(
            tcp_ext.get("ListenDrops", 0)
            + tcp_ext.get("ListenOverflows", 0)
            + tcp_ext.get("SyncookiesSent", 0)
        )
        backlog_rate = self.compute_rate("syn_backlog", backlog_total, now)

        attempt_fail_rate = self.compute_rate(
            "tcp_attempt_fails", float(tcp.get("AttemptFails", 0)), now
        )

        # Packet throughput across all interfaces.
        pps: Optional[float] = None
        try:
            io = psutil.net_io_counters()
            if io is not None:
                pps = self.compute_rate(
                    "net_packets", float(io.packets_recv + io.packets_sent), now
                )
        except Exception as err:
            logger.debug(f"{self.name}: packet counters unavailable: {err}")

        events = []
        network_health: Optional[float] = None
        resource_health: Optional[float] = None

        components = []
        if backlog_rate is not None:
            # Sustained 50 backlog drops/sec is severe SYN pressure
            components.append(self.scale_metric(backlog_rate, 0.0, 50.0, invert=True))
        if attempt_fail_rate is not None:
            components.append(
                self.scale_metric(attempt_fail_rate, 0.0, 100.0, invert=True)
            )
        if pps is not None:
            pps_health = self.scale_metric(pps, 0.0, 50000.0, invert=True)
            components.append(pps_health)
            resource_health = pps_health

        if components:
            network_health = min(components)

        if (backlog_rate is not None and backlog_rate > 10.0) or (
            pps is not None and pps > 30000.0
        ):
            self._syn_flood_count += 1
            events.append(
                SecurityEvent(
                    event_type="ebpf_ddos_syn_flood",
                    source=self.name,
                    target_dimensions=[2, 7],
                    impact=np.array([0, 0, -0.6, 0, 0, 0, 0, -0.4, 0, 0, 0]),
                    severity=0.9,
                    metadata={
                        "packets_per_sec": pps,
                        "syn_backlog_drops_per_sec": backlog_rate,
                    },
                    timestamp=now,
                )
            )

        return self.build_telemetry(
            {
                "network": network_health,
                "resource": resource_health,
            },
            events=events,
            timestamp=now,
        )

    # ------------------------------------------------------------------
    # Explicit simulation entry point (demos, tests, scenario replay)
    # ------------------------------------------------------------------

    def sample_network_probe(
        self,
        pps: float = 1000.0,
        syn_ratio: float = 0.02,
        unauthorized_egress_attempts: int = 0,
        port_scan_signals: int = 0,
    ) -> TelemetryInput:
        """
        Build telemetry from caller-supplied network figures.

        This is a SIMULATION / replay entry point: the caller provides the
        measurements. ``collect()`` never calls it, so live monitoring is
        never fed synthetic values.

        Args:
            pps: Packets per second across network interfaces.
            syn_ratio: Ratio of TCP SYN packets to total packets.
            unauthorized_egress_attempts: Attempts to connect to blocked external IPs.
            port_scan_signals: Distinct target port connection bursts.
        """
        now = time.time()
        events = []

        syn_health = self.scale_metric(syn_ratio * 100.0, 0.0, 40.0, invert=True)
        pps_health = self.scale_metric(pps, 0.0, 50000.0, invert=True)
        network_health = min(syn_health, pps_health)

        if syn_ratio > 0.3 or pps > 30000.0:
            events.append(
                SecurityEvent(
                    event_type="ebpf_ddos_syn_flood",
                    source=self.name,
                    target_dimensions=[2, 7],
                    impact=np.array([0, 0, -0.6, 0, 0, 0, 0, -0.4, 0, 0, 0]),
                    severity=0.9,
                    metadata={"pps": pps, "syn_ratio": syn_ratio},
                    timestamp=now,
                )
            )

        auth_health = self.scale_metric(
            unauthorized_egress_attempts, 0.0, 10.0, invert=True
        )
        execution_health = self.scale_metric(port_scan_signals, 0.0, 20.0, invert=True)

        if unauthorized_egress_attempts > 3:
            self._egress_violations += 1
            events.append(
                SecurityEvent(
                    event_type="ebpf_unauthorized_egress",
                    source=self.name,
                    target_dimensions=[2, 1],
                    impact=np.array([0, -0.3, -0.4, 0, 0, 0, 0, 0, 0, 0, 0]),
                    severity=0.75,
                    metadata={"egress_attempts": unauthorized_egress_attempts},
                    timestamp=now,
                )
            )

        return self.build_telemetry(
            {
                "network": network_health,
                "authorization": auth_health,
                "execution": execution_health,
                "resource": pps_health,
            },
            events=events,
            timestamp=now,
        )
