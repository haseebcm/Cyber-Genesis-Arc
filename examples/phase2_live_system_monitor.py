"""
H¹¹-CGA Phase 2 — Live Host Telemetry Monitoring Demo
======================================================

Demonstrates collecting real system metrics (CPU, RAM, Sockets, Processes)
from the local operating system, normalising them via SystemAdapter,
and processing them through the H¹¹ Cyber Genesis Engine.
"""

import time
from h11_cga import (
    CyberGenesisEngine,
    TelemetryIngestionHub,
    SystemAdapter,
    EBPFNetworkProbe,
    LogAdapter,
    DIMENSION_NAMES,
)


def main() -> None:
    print("=" * 76)
    print("  H11-CGA PHASE 2 -- LIVE SYSTEM TELEMETRY ADAPTER DEMONSTRATION")
    print("=" * 76)

    # 1. Initialize Engine & Telemetry Ingestion Hub
    engine = CyberGenesisEngine()
    hub = TelemetryIngestionHub()

    # 2. Instantiate and register real adapters
    sys_adapter = SystemAdapter(polling_interval=0.5)
    ebpf_adapter = EBPFNetworkProbe(polling_interval=0.5)
    log_adapter = LogAdapter(polling_interval=0.5)

    hub.register_adapter(sys_adapter)
    hub.register_adapter(ebpf_adapter)
    hub.register_adapter(log_adapter)

    print(f"\nRegistered Adapters in Telemetry Hub: {hub.registered_adapters}\n")

    # ------------------------------------------------------------------
    # Step A: Sample 5 live baseline ticks from actual OS hardware
    # ------------------------------------------------------------------
    print("Step A: Collecting 5 live telemetry ticks from host system...")
    for i in range(5):
        telemetry = hub.collect_all()
        assessment = engine.process_tick(telemetry)

        print(
            f"  Tick #{i+1:02d} | Status: {assessment.status.value:12s} | "
            f"G_c = {assessment.genesis_value:+.4f} | DR = {assessment.dr_value:.4f} | "
            f"HSA = {assessment.hsa_coordinate:+.4f}"
        )
        time.sleep(0.3)

    # Print baseline 11-D state vector
    latest = engine.get_assessment_history()[-1]
    print("\n  Live 11-D Host Security State Vector:")
    for j, name in enumerate(DIMENSION_NAMES):
        val = latest.current_state[j]
        bar = "#" * int(val * 25) + "-" * (25 - int(val * 25))
        print(f"    {name:15s} [{bar}] {val:.3f}")

    # ------------------------------------------------------------------
    # Step B: Parse an incoming suspicious log line via LogAdapter
    # ------------------------------------------------------------------
    print("\n" + "-" * 76)
    print("Step B: Simulating incoming log event ingestion...")
    print("-" * 76)

    log_adapter.parse_log_line("Aug 16 12:00:00 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2")
    log_adapter.parse_log_line("Aug 16 12:00:01 server kernel: Out of memory: Kill process 9999 (malware)")

    telemetry_log = hub.collect_all()
    print(f"  Captured {len(telemetry_log.events)} security events from LogAdapter.")

    assessment_log = engine.process_tick(telemetry_log)
    print(
        f"  Post-Log Tick | Status: {assessment_log.status.value:12s} | "
        f"G_c = {assessment_log.genesis_value:+.4f} | DR = {assessment_log.dr_value:.4f}"
    )

    if assessment_log.recommended_actions:
        print(f"\n  Recommended Responses:")
        for action in assessment_log.recommended_actions[:3]:
            print(f"    -> [{action.urgency.value:8s}] {action.action_type.value:20s} target={action.target}")

    # ------------------------------------------------------------------
    # Step C: Recovery
    # ------------------------------------------------------------------
    print("\n" + "-" * 76)
    print("Step C: System state recovery loop (3 ticks)...")
    print("-" * 76)

    for k in range(3):
        telemetry_rec = hub.collect_all()
        a_rec = engine.process_tick(telemetry_rec)
        print(
            f"  Recovery Tick #{k+1} | Status: {a_rec.status.value:12s} | "
            f"G_c = {a_rec.genesis_value:+.4f} | DR = {a_rec.dr_value:.4f}"
        )
        time.sleep(0.3)

    print(f"\n{'=' * 76}")
    print("  * Phase 2 Live Telemetry Monitoring Demo complete.")
    print(f"{'=' * 76}\n")


if __name__ == "__main__":
    main()
