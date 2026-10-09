"""Synthetic response report. No external product comparison is measured."""
from h11_cga import RedTeamBenchmarkEngine


def main():
    report = RedTeamBenchmarkEngine().run_full_benchmark()
    print("H11-CGA synthetic scenario response report")
    print("External SIEM/EDR comparison and cascade suppression: unavailable")
    for result in report.results:
        print(f"{result.scenario_name}: detected={result.h11_detected}, tick={result.h11_detection_tick}, min_G={result.h11_min_gc:.4f}, actions={result.h11_actions_generated}")
    print(f"Synthetic detection rate: {report.h11_detection_rate_pct:.1f}% over {report.total_scenarios} constructed scenarios")


if __name__ == "__main__":
    main()
