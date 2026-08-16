"""
H¹¹-CGA Phase 3 — Red-Team Benchmark & Report Generator
=========================================================

Executes 10 complex attack scenarios, comparing H¹¹-CGA state-space
convergence against traditional rule-based SIEM/EDR baselines.
"""

from h11_cga import RedTeamBenchmarkEngine


def main() -> None:
    print("=" * 78)
    print("  H11-CGA PHASE 3 -- RED-TEAM ATTACK BENCHMARK & COMPARATIVE REPORT")
    print("=" * 78)
    print("  Executing 10 attack campaign benchmarks against H11-CGA vs SIEM/EDR...\n")

    benchmark_engine = RedTeamBenchmarkEngine()
    report = benchmark_engine.run_full_benchmark()

    # Print summary header
    print(f"  TOTAL SCENARIOS EVALUATED: {report.total_scenarios}")
    print(f"  H11-CGA Detection Rate:    {report.h11_detection_rate_pct:.1f}%")
    print(f"  SIEM/EDR Detection Rate:   {report.trad_detection_rate_pct:.1f}%")
    print(f"  Average Detection Speedup: {report.avg_speedup_ratio:.2f}x faster")
    print(f"  Avg Cascade Suppression:   {report.avg_cascade_suppression_pct:.1f}%\n")

    print("-" * 78)
    print(f"  {'Scenario Name':32s} | {'H11 Speed':>9s} | {'SIEM Speed':>10s} | {'Speedup':>7s}")
    print("-" * 78)

    for res in report.results:
        print(
            f"  {res.scenario_name[:32]:32s} | "
            f"Tick #{res.h11_detection_tick:<3d} | "
            f"Tick #{res.trad_detection_tick:<4d} | "
            f"{res.detection_speedup_ratio:6.2f}x"
        )

    print("-" * 78)

    # Detailed report section
    print("\n" + "=" * 78)
    print("  DETAILED SCENARIO INSIGHTS")
    print("=" * 78)

    for i, res in enumerate(report.results, 1):
        print(f"\n[{i:02d}] {res.scenario_name}")
        print(f"     Description:     {res.description}")
        print(f"     H11 Response:    Detected at Tick #{res.h11_detection_tick} | Min G_c = {res.h11_min_gc:+.4f} | Max DR = {res.h11_max_dr:.4f} [{res.h11_hsa_zone.value}]")
        print(f"     Traditional:     Detected at Tick #{res.trad_detection_tick} | Alerts Generated = {res.trad_alert_count} | Missed Windows = {res.trad_false_negatives}")
        print(f"     Impact Ratio:    {res.detection_speedup_ratio:.2f}x faster detection | {res.cascade_suppression_pct:.1f}% cascade suppression")

    print(f"\n{'=' * 78}")
    print("  * Red-Team Attack Benchmark Execution complete.")
    print(f"{'=' * 78}\n")


if __name__ == "__main__":
    main()
