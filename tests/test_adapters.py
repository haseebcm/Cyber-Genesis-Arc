"""
H¹¹-CGA Phase 2 Adapter Unit Tests
====================================
Tests for SystemAdapter, KubernetesAdapter, EBPFNetworkProbe, LogAdapter,
and TelemetryIngestionHub.
"""

import pytest
import numpy as np
import time

from h11_cga import (
    CyberGenesisEngine,
    SystemAdapter,
    KubernetesAdapter,
    EBPFNetworkProbe,
    LogAdapter,
    TelemetryIngestionHub,
    TelemetryInput,
    SecurityEvent,
    NUM_DIMENSIONS,
)


def test_system_adapter_collect():
    adapter = SystemAdapter()
    adapter.start()
    assert adapter.is_active() is True

    telemetry = adapter.collect()
    assert isinstance(telemetry, TelemetryInput)
    assert len(telemetry.raw_values) > 0

    # Only genuinely measured dimensions may be reported
    for key, val in telemetry.raw_values.items():
        assert key in adapter.measured_dimensions, f"'{key}' is not measured"
        assert 0.0 <= val <= 1.0, f"Metric '{key}' out of range: {val}"

    # Behavioural dimensions have no honest host-OS source
    assert "authorization" not in telemetry.raw_values
    assert "governance" not in telemetry.raw_values
    assert "trust" not in telemetry.raw_values

    adapter.stop()
    assert adapter.is_active() is False


def test_system_adapter_reports_io_rate_not_cumulative_total():
    adapter = SystemAdapter()
    adapter.start()

    # First sample cannot yield a rate, so 'data' must be omitted rather
    # than derived from a cumulative since-boot counter.
    first = adapter.collect()
    assert "data" not in first.raw_values

    second = adapter.collect()
    if "data" in second.raw_values:
        assert 0.0 <= second.raw_values["data"] <= 1.0

    adapter.stop()


def test_k8s_adapter_simulation():
    adapter = KubernetesAdapter()
    adapter.start()

    telemetry = adapter.simulate_cluster_telemetry(
        pod_restarts=8,
        api_latency_ms=100.0,
        unauthorized_api_calls=15,
        cpu_quota_utilization=0.8,
        memory_quota_utilization=0.9,
    )
    assert isinstance(telemetry, TelemetryInput)
    assert len(telemetry.events) >= 1
    assert telemetry.events[0].event_type in (
        "k8s_pod_crash_loop",
        "k8s_unauthorized_api_attempts",
    )

    adapter.stop()


def test_ebpf_network_probe():
    probe = EBPFNetworkProbe()
    probe.start()

    # Simulate SYN flood attack
    telemetry = probe.sample_network_probe(
        pps=40000.0,
        syn_ratio=0.5,
        unauthorized_egress_attempts=5,
    )
    assert isinstance(telemetry, TelemetryInput)
    assert len(telemetry.events) >= 1
    assert telemetry.events[0].event_type == "ebpf_ddos_syn_flood"
    assert telemetry.raw_values["network"] < 0.5

    probe.stop()


def test_log_adapter_parsing():
    adapter = LogAdapter()
    adapter.start()

    # Test regex parsing
    event_ssh = adapter.parse_log_line("Failed password for invalid user admin from 10.0.0.1 port 22")
    assert event_ssh is not None
    assert event_ssh.event_type == "ssh_auth_failure"

    event_oom = adapter.parse_log_line("Out of memory: Kill process 1234 (python)")
    assert event_oom is not None
    assert event_oom.event_type == "kernel_oom_killer"

    # Test JSON log parsing
    json_event = adapter.ingest_json_log({
        "event_type": "k8s_token_abuse",
        "status": "unauthorized",
        "action": "privilege_escalation",
        "severity": 0.85,
    })
    assert json_event is not None
    assert json_event.event_type == "k8s_token_abuse"

    telemetry = adapter.collect()
    assert len(telemetry.events) == 3

    adapter.stop()


def test_telemetry_ingestion_hub():
    hub = TelemetryIngestionHub()
    sys_adapter = SystemAdapter()
    ebpf_probe = EBPFNetworkProbe()
    log_adapter = LogAdapter()

    hub.register_adapter(sys_adapter)
    hub.register_adapter(ebpf_probe)
    hub.register_adapter(log_adapter)

    assert len(hub.registered_adapters) == 3

    # Add a log event
    log_adapter.parse_log_line("Failed password for user root from 1.2.3.4")

    # Collect merged telemetry
    merged = hub.collect_all()
    assert isinstance(merged, TelemetryInput)
    assert len(merged.events) >= 1

    # Every reported dimension must trace back to an adapter that measured it
    provenance = hub.last_provenance
    for dim in merged.raw_values:
        assert provenance.get(dim), f"'{dim}' reported with no measuring source"
        assert 0.0 <= merged.raw_values[dim] <= 1.0

    # Verify integration with CyberGenesisEngine
    engine = CyberGenesisEngine()
    assessment = engine.process_tick(merged)
    assert assessment.genesis_value is not None
    assert assessment.status is not None

    hub.unregister_adapter("SystemHostAdapter")
    assert "SystemHostAdapter" not in hub.registered_adapters


def test_k8s_adapter_unavailable_without_cluster_source():
    adapter = KubernetesAdapter()
    adapter.start()

    assert adapter.is_available() is False
    assert "metrics_provider" in adapter.unavailable_reason()

    # An unconfigured cluster adapter must invent nothing
    assert adapter.collect().raw_values == {}

    adapter.stop()


def test_k8s_adapter_uses_configured_metrics_provider():
    adapter = KubernetesAdapter(
        metrics_provider=lambda: {
            "pod_restarts": 8,
            "api_latency_ms": 100.0,
            "unauthorized_api_calls": 15,
            "cpu_quota_utilization": 0.8,
            "memory_quota_utilization": 0.9,
        }
    )
    adapter.start()

    assert adapter.is_available() is True
    telemetry = adapter.collect()

    assert telemetry.raw_values["authorization"] < 0.5
    assert len(telemetry.events) >= 1
    for key in telemetry.raw_values:
        assert key in adapter.measured_dimensions

    adapter.stop()


def test_hub_skips_unavailable_adapters():
    hub = TelemetryIngestionHub()
    k8s = KubernetesAdapter()
    log_adapter = LogAdapter()

    hub.register_adapter(k8s)
    hub.register_adapter(log_adapter)

    merged = hub.collect_all()

    assert "KubernetesAdapter" in hub.last_skipped
    assert "KubernetesAdapter" not in hub.measuring_adapters
    # No source measured any dimension, so nothing may be reported
    assert merged.raw_values == {}


def test_adapters_never_pad_unmeasured_dimensions():
    """Regression guard: adapters must not emit nominal filler values."""
    for adapter in (SystemAdapter(), EBPFNetworkProbe(), KubernetesAdapter(), LogAdapter()):
        adapter.start()
        raw = adapter.collect().raw_values
        assert set(raw).issubset(set(adapter.measured_dimensions))
        adapter.stop()
