"""
H¹¹-CGA Command Line Interface & Monitoring Daemon
===================================================

Command-line entry point (`h11-monitor`) for real-time live host OS
state monitoring, divergence detection, and HSA trajectory tracking.
"""

from __future__ import annotations

import argparse
import sys
import time

from h11_cga import (
    CyberGenesisEngine,
    TelemetryIngestionHub,
    SystemAdapter,
    EBPFNetworkProbe,
    DIMENSION_NAMES,
    SystemStatus,
)


def run_monitor(duration: float = 0.0, interval: float = 1.0) -> None:
    """
    Run the H¹¹-CGA live host monitor.

    Args:
        duration: Run time in seconds (0 = run indefinitely until Ctrl+C).
        interval: Polling interval between ticks in seconds.
    """
    print("\n" + "=" * 76)
    print("  H11 CYBER GENESIS ARCHITECTURE (H11-CGA) -- LIVE SYSTEM MONITOR")
    print("=" * 76)

    # Initialize Engine & Hub
    engine = CyberGenesisEngine()
    hub = TelemetryIngestionHub()

    # Register adapters
    sys_adapter = SystemAdapter(polling_interval=interval)
    ebpf_adapter = EBPFNetworkProbe(polling_interval=interval)
    hub.register_adapter(sys_adapter)
    hub.register_adapter(ebpf_adapter)

    print(f"  Initialized CyberGenesisEngine with {len(hub.registered_adapters)} active adapters:")
    for name in hub.registered_adapters:
        print(f"   -> {name}")
    print(f"  Polling interval: {interval}s")
    print("=" * 76 + "\n")

    start_time = time.time()
    tick_count = 0

    try:
        while True:
            # 1. Collect merged telemetry from adapters
            telemetry = hub.collect_all()

            # 2. Run one full control loop cycle
            assessment = engine.process_tick(telemetry)
            tick_count += 1

            status = assessment.status.value
            gc = assessment.genesis_value

            print(f"[Tick #{tick_count:04d}] Status: {status:12s} | G_c(t) = {gc:+.4f} | "
                  f"DR_c = {assessment.dr_value:.4f} | HSA = {assessment.hsa_coordinate:+.4f} [{assessment.hsa_zone.value}]")

            # Print degraded dimensions if any
            degraded = []
            for i, name in enumerate(DIMENSION_NAMES):
                val = assessment.current_state[i]
                if val < 0.9:
                    degraded.append((name, val))

            if degraded:
                print("   Degraded dimensions:")
                for name, val in sorted(degraded, key=lambda x: x[1]):
                    bar = "#" * int(val * 20) + "-" * (20 - int(val * 20))
                    print(f"     * {name:15s} [{bar}] {val:.3f}")

            if assessment.recommended_actions:
                print(f"   Recommended Actions ({len(assessment.recommended_actions)}):")
                for action in assessment.recommended_actions[:3]:
                    print(f"     -> [{action.urgency.value:8s}] {action.action_type.value:20s} target={action.target}")

            print("-" * 76)

            # Check duration stop condition
            if duration > 0 and (time.time() - start_time) >= duration:
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n* Monitoring stopped by user.")

    print(f"\nCompleted {tick_count} ticks. Final System Status: {engine.get_system_status().value}\n")


def main() -> None:
    """CLI Parser Entrypoint."""
    parser = argparse.ArgumentParser(
        description="H11-CGA Live System Monitoring Daemon & Engine Console."
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="Run duration in seconds (0 = continuous).",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Telemetry collection interval in seconds (default: 1.0).",
    )
    args = parser.parse_args()

    run_monitor(duration=args.duration, interval=args.interval)


if __name__ == "__main__":
    main()
