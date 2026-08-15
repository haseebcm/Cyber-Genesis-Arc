"""
H¹¹-CGA Attack Scenarios
=========================

Demonstrates the architecture's response to different attack patterns:
1. Identity Compromise -> Privilege Escalation -> Data Exfiltration (cascade)
2. DDoS (network dimension spike)
3. Insider Threat (slow divergence across multiple dimensions)
4. Zero-Day (sudden state transition)

Each scenario shows: divergence detection, cascade analysis,
ΔCR prioritization, and containment response.
"""

from h11_cga import CyberGenesisEngine, DIMENSION_NAMES


def print_header(title: str) -> None:
    print(f"\n{'=' * 74}")
    print(f"  * {title}")
    print(f"{'=' * 74}")


def print_assessment(assessment, label: str = "") -> None:
    """Print a concise assessment summary."""
    if label:
        print(f"\n  -- {label} --")

    # Status bar
    status = assessment.status.value
    gc = assessment.genesis_value
    print(f"  Status: {status:12s}  G_c = {gc:+.4f}")
    print(f"     DR = {assessment.dr_value:.4f}  "
          f"HSA = {assessment.hsa_coordinate:+.4f} [{assessment.hsa_zone.value}]  "
          f"CCI = {assessment.cci_value:.4f}")
    print(f"     Buffer = {assessment.security_buffer:.4f}  "
          f"Limit = {assessment.limit_utilization:.4f}  "
          f"Permission = {assessment.permission}")

    # Show degraded dimensions
    degraded = []
    for i, name in enumerate(DIMENSION_NAMES):
        val = assessment.current_state[i]
        if val < 0.9:
            degraded.append((name, val))
    if degraded:
        print(f"     Degraded dimensions:")
        for name, val in sorted(degraded, key=lambda x: x[1]):
            bar_len = int(val * 20)
            bar = "#" * bar_len + "-" * (20 - bar_len)
            print(f"       {name:15s} [{bar}] {val:.3f}")

    # Show top actions
    if assessment.recommended_actions:
        print(f"     Actions ({len(assessment.recommended_actions)}):")
        for a in assessment.recommended_actions[:3]:
            print(f"       -> [{a.urgency.value:8s}] {a.action_type.value} {a.target}")


def scenario_cascade_attack() -> None:
    """Scenario 1: Multi-stage cascade — Identity -> Privilege -> Data."""
    print_header("SCENARIO 1: CASCADING ATTACK")
    print("  Identity Compromise -> Privilege Escalation -> Data Exfiltration")
    print("  This demonstrates CCI cascade detection and multi-stage response.\n")

    engine = CyberGenesisEngine()

    # Stage 0: Nominal
    a = engine.process_tick()
    print_assessment(a, "STAGE 0 - Baseline")

    # Stage 1: Identity compromise
    a = engine.inject_attack("identity_compromise", severity=0.5)
    print_assessment(a, "STAGE 1 - Identity Compromise (sev=0.5)")

    # Stage 2: Privilege escalation follows
    a = engine.inject_attack("privilege_escalation", severity=0.6)
    print_assessment(a, "STAGE 2 - Privilege Escalation (sev=0.6)")

    # Stage 3: Data exfiltration
    a = engine.inject_attack("data_exfiltration", severity=0.7)
    print_assessment(a, "STAGE 3 - Data Exfiltration (sev=0.7)")

    # Stage 4: Recovery ticks
    print(f"\n  -- RECOVERY --")
    for i in range(8):
        a = engine.process_tick()
        gc = a.genesis_value
        bar = "#" * max(0, int((gc + 1) * 15)) + "-" * max(0, 30 - int((gc + 1) * 15))
        print(f"    Tick {i + 1}: [{bar}] G_c={gc:+.4f}  {a.status.value}")


def scenario_ddos() -> None:
    """Scenario 2: DDoS attack — sudden network/resource spike."""
    print_header("SCENARIO 2: DDoS ATTACK")
    print("  Massive network and resource dimension spike.\n")

    engine = CyberGenesisEngine()

    a = engine.process_tick()
    print_assessment(a, "BASELINE")

    # Severe DDoS
    a = engine.inject_attack("ddos", severity=0.9)
    print_assessment(a, "DDoS STRIKE (sev=0.9)")

    # Sustained pressure — additional ticks under load
    for i in range(3):
        a = engine.inject_attack("ddos", severity=0.3)
        print_assessment(a, f"SUSTAINED PRESSURE - Tick {i + 1}")


def scenario_insider_threat() -> None:
    """Scenario 3: Insider threat — slow, multi-dimensional divergence."""
    print_header("SCENARIO 3: INSIDER THREAT")
    print("  Slow divergence across Trust, Identity, Governance, Data.")
    print("  Tests whether HSA detects the gradual approach to singularity.\n")

    engine = CyberGenesisEngine()

    a = engine.process_tick()
    print_assessment(a, "BASELINE")

    # Gradual escalation over 6 ticks
    severities = [0.1, 0.15, 0.2, 0.25, 0.3, 0.4]
    for i, sev in enumerate(severities):
        a = engine.inject_attack("insider_threat", severity=sev)
        print_assessment(a, f"ESCALATION {i + 1} (sev={sev})")


def scenario_zero_day() -> None:
    """Scenario 4: Zero-day — sudden, severe state transition."""
    print_header("SCENARIO 4: ZERO-DAY EXPLOIT")
    print("  Sudden severe impact on Execution, Memory, Compute, Recovery.")
    print("  Tests the architecture's response to abrupt state changes.\n")

    engine = CyberGenesisEngine()

    a = engine.process_tick()
    print_assessment(a, "BASELINE")

    # Zero-day strike
    a = engine.inject_attack("zero_day", severity=0.85)
    print_assessment(a, "ZERO-DAY STRIKE (sev=0.85)")

    # Follow-up lateral movement
    a = engine.inject_attack("lateral_movement", severity=0.6)
    print_assessment(a, "LATERAL MOVEMENT (sev=0.6)")

    # Genesis equation breakdown
    print(f"\n  Genesis Equation Breakdown:")
    for term, value in a.genesis_terms.items():
        print(f"    {term:30s} = {value:+.6f}")


def main() -> None:
    print("=" * 74)
    print("  H11 CYBER GENESIS ARCHITECTURE - ATTACK SCENARIO DEMONSTRATIONS")
    print("=" * 74)

    scenario_cascade_attack()
    scenario_ddos()
    scenario_insider_threat()
    scenario_zero_day()

    print(f"\n{'=' * 74}")
    print("  * All scenarios complete.")
    print(f"{'=' * 74}\n")


if __name__ == "__main__":
    main()
