"""
H¹¹-CGA Kubernetes Telemetry Adapter
====================================

Container & Kubernetes Pod/Cluster Telemetry Normalizer mapping
orchestration health into the MCC Security State Vector dimensions.

This adapter has no ambient data source. It reports telemetry only when a
``metrics_provider`` callable is supplied to read from a real cluster (K8s
API server, cAdvisor, or metrics-server). Without one, ``is_available()``
returns False and the ingestion hub skips it, so an unconfigured cluster
adapter never contributes invented pod health to the security state.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

import numpy as np

from h11_cga.adapters.base import BaseTelemetryAdapter
from h11_cga.types import (
    TelemetryInput,
    SecurityEvent,
    NUM_DIMENSIONS,
)

logger = logging.getLogger(__name__)

ClusterMetrics = Mapping[str, float]
MetricsProvider = Callable[[], ClusterMetrics]


class KubernetesAdapter(BaseTelemetryAdapter):
    """
    Kubernetes & Container Telemetry Adapter.

    Args:
        metrics_provider: Callable returning live cluster figures with keys
            ``pod_restarts``, ``api_latency_ms``, ``unauthorized_api_calls``,
            ``cpu_quota_utilization``, and ``memory_quota_utilization``.
            When omitted the adapter reports itself unavailable.
    """

    def __init__(
        self,
        polling_interval: float = 1.0,
        metrics_provider: Optional[MetricsProvider] = None,
    ) -> None:
        super().__init__(name="KubernetesAdapter", polling_interval=polling_interval)
        self._metrics_provider = metrics_provider
        self._pod_restarts: int = 0
        self._unauthorized_api_calls: int = 0

    @property
    def measured_dimensions(self) -> Tuple[str, ...]:
        return (
            "authorization",
            "compute",
            "memory",
            "execution",
            "resource",
            "governance",
            "recovery",
        )

    def is_available(self) -> bool:
        """True only when a real cluster metrics provider is configured."""
        return self._metrics_provider is not None

    def unavailable_reason(self) -> str:
        if self.is_available():
            return ""
        return "no cluster metrics_provider configured (K8s API/cAdvisor source required)"

    def set_metrics_provider(self, provider: Optional[MetricsProvider]) -> None:
        """Attach or detach the live cluster metrics source."""
        self._metrics_provider = provider

    def collect(self) -> TelemetryInput:
        """Pull live cluster metrics, or emit nothing when unconfigured."""
        if self._metrics_provider is None:
            return self.build_telemetry({}, events=[], timestamp=time.time())

        try:
            metrics = self._metrics_provider()
        except Exception as err:
            logger.error(f"{self.name}: cluster metrics provider failed: {err}")
            return self.build_telemetry({}, events=[], timestamp=time.time())

        return self._normalize(
            pod_restarts=int(metrics.get("pod_restarts", 0)),
            api_latency_ms=float(metrics.get("api_latency_ms", 0.0)),
            unauthorized_api_calls=int(metrics.get("unauthorized_api_calls", 0)),
            cpu_quota_utilization=float(metrics.get("cpu_quota_utilization", 0.0)),
            memory_quota_utilization=float(metrics.get("memory_quota_utilization", 0.0)),
        )

    def simulate_cluster_telemetry(
        self,
        pod_restarts: int = 0,
        api_latency_ms: float = 15.0,
        unauthorized_api_calls: int = 0,
        cpu_quota_utilization: float = 0.4,
        memory_quota_utilization: float = 0.5,
    ) -> TelemetryInput:
        """
        Build telemetry from caller-supplied cluster figures.

        Explicit SIMULATION / replay entry point for demos and tests.
        ``collect()`` never calls it.

        Args:
            pod_restarts: Number of container CrashLoopBackOffs or restarts.
            api_latency_ms: K8s API server response latency in ms.
            unauthorized_api_calls: Number of 401/403 API responses.
            cpu_quota_utilization: Pod CPU usage ratio against limit.
            memory_quota_utilization: Pod RAM usage ratio against limit.
        """
        return self._normalize(
            pod_restarts=pod_restarts,
            api_latency_ms=api_latency_ms,
            unauthorized_api_calls=unauthorized_api_calls,
            cpu_quota_utilization=cpu_quota_utilization,
            memory_quota_utilization=memory_quota_utilization,
        )

    def _normalize(
        self,
        pod_restarts: int,
        api_latency_ms: float,
        unauthorized_api_calls: int,
        cpu_quota_utilization: float,
        memory_quota_utilization: float,
    ) -> TelemetryInput:
        """Map cluster figures onto the dimensions this adapter measures."""
        now = time.time()
        events = []

        self._pod_restarts = pod_restarts
        self._unauthorized_api_calls = unauthorized_api_calls

        compute_health = self.scale_metric(
            cpu_quota_utilization * 100.0, 0.0, 95.0, invert=True
        )
        memory_health = self.scale_metric(
            memory_quota_utilization * 100.0, 0.0, 95.0, invert=True
        )
        # Resource pressure is the worst of the two quota headrooms.
        resource_health = min(compute_health, memory_health)

        recovery_health = self.scale_metric(pod_restarts, 0.0, 10.0, invert=True)
        execution_health = self.scale_metric(pod_restarts, 0.0, 5.0, invert=True)

        if pod_restarts > 5:
            events.append(
                SecurityEvent(
                    event_type="k8s_pod_crash_loop",
                    source=self.name,
                    target_dimensions=[6, 10],
                    impact=np.array([0, 0, 0, 0, 0, 0, -0.4, 0, 0, 0, -0.3]),
                    severity=0.85,
                    metadata={"pod_restarts": pod_restarts},
                    timestamp=now,
                )
            )

        auth_health = self.scale_metric(unauthorized_api_calls, 0.0, 20.0, invert=True)
        governance_health = self.scale_metric(api_latency_ms, 5.0, 500.0, invert=True)

        if unauthorized_api_calls > 10:
            events.append(
                SecurityEvent(
                    event_type="k8s_unauthorized_api_attempts",
                    source=self.name,
                    target_dimensions=[1, 9],
                    impact=np.array([0, -0.4, 0, 0, 0, 0, 0, 0, 0, -0.3, 0]),
                    severity=0.8,
                    metadata={"unauthorized_calls": unauthorized_api_calls},
                    timestamp=now,
                )
            )

        return self.build_telemetry(
            {
                "authorization": auth_health,
                "compute": compute_health,
                "memory": memory_health,
                "execution": execution_health,
                "resource": resource_health,
                "governance": governance_health,
                "recovery": recovery_health,
            },
            events=events,
            timestamp=now,
        )
