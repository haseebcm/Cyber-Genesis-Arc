"""
H¹¹-CGA Kubernetes Telemetry Adapter
====================================

Container & Kubernetes Pod/Cluster Telemetry Normalizer mapping
orchestration health into the 11 MCC Security State Vector dimensions.
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


class KubernetesAdapter(BaseTelemetryAdapter):
    """
    Kubernetes & Container Telemetry Adapter.

    Simulates or connects to K8s API server / cAdvisor metrics to track pod health,
    restart rates, service token access, API server latency, and quota utilization.
    """

    def __init__(self, polling_interval: float = 1.0) -> None:
        super().__init__(name="KubernetesAdapter", polling_interval=polling_interval)
        self._pod_restarts: int = 0
        self._unauthorized_api_calls: int = 0

    def simulate_cluster_telemetry(
        self,
        pod_restarts: int = 0,
        api_latency_ms: float = 15.0,
        unauthorized_api_calls: int = 0,
        cpu_quota_utilization: float = 0.4,
        memory_quota_utilization: float = 0.5,
    ) -> TelemetryInput:
        """
        Ingest or simulate container cluster telemetry parameters.

        Args:
            pod_restarts: Number of container CrashLoopBackOffs or restarts.
            api_latency_ms: K8s API server response latency in ms.
            unauthorized_api_calls: Number of 401/403 API responses.
            cpu_quota_utilization: Pod CPU usage ratio against limit.
            memory_quota_utilization: Pod RAM usage ratio against limit.
        """
        now = time.time()
        events = []

        # --- 1. Compute & Resource Dimension ---
        compute_health = self.scale_metric(cpu_quota_utilization * 100, 0.0, 95.0, invert=True)
        resource_health = self.scale_metric(memory_quota_utilization * 100, 0.0, 95.0, invert=True)

        # --- 2. Recovery & Execution Dimension ---
        recovery_health = self.scale_metric(pod_restarts, 0.0, 10.0, invert=True)
        execution_health = self.scale_metric(pod_restarts, 0.0, 5.0, invert=True)

        if pod_restarts > 5:
            events.append(
                SecurityEvent(
                    event_type="k8s_pod_crash_loop",
                    source=self.name,
                    target_dimensions=[6, 10],  # Execution, Recovery
                    impact=np.array([0, 0, 0, 0, 0, 0, -0.4, 0, 0, 0, -0.3]),
                    severity=0.85,
                    metadata={"pod_restarts": pod_restarts},
                    timestamp=now,
                )
            )

        # --- 3. Governance & Authorization Dimension ---
        auth_health = self.scale_metric(unauthorized_api_calls, 0.0, 20.0, invert=True)
        governance_health = self.scale_metric(api_latency_ms, 5.0, 500.0, invert=True)

        if unauthorized_api_calls > 10:
            events.append(
                SecurityEvent(
                    event_type="k8s_unauthorized_api_attempts",
                    source=self.name,
                    target_dimensions=[1, 9],  # Authorization, Governance
                    impact=np.array([0, -0.4, 0, 0, 0, 0, 0, 0, 0, -0.3, 0]),
                    severity=0.8,
                    metadata={"unauthorized_calls": unauthorized_api_calls},
                    timestamp=now,
                )
            )

        # --- 4. Identity & Trust Dimension ---
        identity_health = 0.95
        trust_health = float(np.clip(0.9 - (unauthorized_api_calls * 0.02), 0.0, 1.0))

        raw_values = {
            "identity": identity_health,
            "authorization": auth_health,
            "network": 0.95,
            "data": 0.95,
            "compute": compute_health,
            "memory": resource_health,
            "execution": execution_health,
            "resource": resource_health,
            "trust": trust_health,
            "governance": governance_health,
            "recovery": recovery_health,
        }

        return TelemetryInput(
            raw_values=raw_values,
            events=events,
            timestamp=now,
        )

    def collect(self) -> TelemetryInput:
        """Sample default container metrics."""
        return self.simulate_cluster_telemetry()
