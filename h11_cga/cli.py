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

import numpy as np

from h11_cga import (
    CyberGenesisEngine,
    TelemetryIngestionHub,
    SystemAdapter,
    EBPFNetworkProbe,
    CGAConfig,
    DIMENSION_NAMES,
    SystemStatus,
)


def run_monitor(
    duration: float = 0.0, interval: float = 1.0, calibrate_ticks: int = 10
) -> None:
    """
    Run the H¹¹-CGA live host monitor.

    Args:
        duration: Run time in seconds (0 = run indefinitely until Ctrl+C).
        interval: Polling interval between ticks in seconds.
        calibrate_ticks: Warmup ticks used to learn this host's baseline.
    """
    print("\n" + "=" * 76)
    print("  H11 CYBER GENESIS ARCHITECTURE (H11-CGA) -- LIVE SYSTEM MONITOR")
    print("=" * 76)

    # A live host never idles at the ideal all-nominal vector, so learn its
    # working baseline before treating divergence as a threat signal.
    config = CGAConfig(baseline_calibration_ticks=max(0, calibrate_ticks))
    engine = CyberGenesisEngine(config)
    hub = TelemetryIngestionHub()

    # Register adapters
    sys_adapter = SystemAdapter(polling_interval=interval)
    ebpf_adapter = EBPFNetworkProbe(polling_interval=interval)
    hub.register_adapter(sys_adapter)
    hub.register_adapter(ebpf_adapter)

    measuring = hub.measuring_adapters
    print(f"  Initialized CyberGenesisEngine with {len(measuring)} measuring adapter(s):")
    for line in hub.describe_sources():
        print(f"   -> {line}")
    if not measuring:
        print("   !! No adapter has a reachable data source; telemetry will be empty.")
    print(f"  Polling interval: {interval}s")
    if calibrate_ticks > 0:
        print(f"  Baseline calibration: learning host baseline over {calibrate_ticks} ticks")
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

            if engine.is_calibrating:
                observed, required = engine.get_calibration_progress()
                print(f"[Tick #{tick_count:04d}] CALIBRATING baseline ({observed}/{required})")
                if duration > 0 and (time.time() - start_time) >= duration:
                    break
                time.sleep(interval)
                continue

            print(f"[Tick #{tick_count:04d}] Status: {status:12s} | G_c(t) = {gc:+.4f} | "
                  f"DR_c = {assessment.dr_value:.4f} | HSA = {assessment.hsa_coordinate:+.4f} [{assessment.hsa_zone.value}]")

            # Report dimensions that drifted outside the learned envelope
            degraded = []
            for i, name in enumerate(DIMENSION_NAMES):
                val = assessment.current_state[i]
                if val < assessment.baseline.lower_bound[i]:
                    degraded.append((name, val))

            if degraded:
                print("   Degraded dimensions:")
                for name, val in sorted(degraded, key=lambda x: x[1]):
                    bar = "#" * int(val * 20) + "-" * (20 - int(val * 20))
                    print(f"     * {name:15s} [{bar}] {val:.3f}")

            if assessment.origin_hypotheses:
                top = assessment.origin_hypotheses[0]
                print(f"   Likely origin:  {top.name} "
                      f"(score {top.score:.3f}, explains {top.explained_fraction:.0%})")

            # Low coherence means the host moved in ways T_c does not model,
            # which is worth surfacing even when divergence itself is small.
            if assessment.coherence < 0.9:
                worst_idx = int(np.argmax(np.abs(assessment.unexplained_vector)))
                print(f"   Model coherence: {assessment.coherence:.3f} "
                      f"(largest unexplained move: {DIMENSION_NAMES[worst_idx]})")

            if assessment.permission_debt > 0:
                print(f"   Permission debt: {assessment.permission_debt:.2f} "
                      f"(trust withheld until repaid)")

            law_report = assessment.law_conformance
            if law_report is not None and not law_report.sovereign:
                if not law_report.origin_defined:
                    print("   Law audit:       Phi_0 UNDEFINED "
                          "(root signature gone; system does not exist)")
                else:
                    broken = law_report.violated
                    print(f"   Law audit:       Phi_0={law_report.origin_flux:.3f}  "
                          f"S_ig={law_report.sovereign_signature:.3f}  "
                          f"Phi_H11={law_report.phi_h11:.3f}")
                    for law in sorted(broken, key=lambda l: l.conformance)[:3]:
                        print(f"     ! Law {law.law:2d} {law.name:11s} "
                              f"{law.measured:+.4f} vs {law.required:+.1f} required "
                              f"-> {law.verdict.value}")

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
    parser.add_argument(
        "--calibrate",
        type=int,
        default=10,
        help="Warmup ticks used to learn this host's baseline (0 = assume ideal).",
    )
    args = parser.parse_args()

    run_monitor(
        duration=args.duration,
        interval=args.interval,
        calibrate_ticks=args.calibrate,
    )


if __name__ == "__main__":
    main()
