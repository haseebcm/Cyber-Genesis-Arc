"""
H¹¹-CGA Basic Usage Example
============================

Demonstrates the core functionality of the Cyber Genesis Architecture:
- Creating the engine
- Running the control loop
- Reading the Genesis Equation output
- Understanding the security state
"""

from h11_cga import (
    CyberGenesisEngine,
    TelemetryInput,
    SecurityEvent,
    CGAConfig,
    NUM_DIMENSIONS,
    DIMENSION_NAMES,
)
import numpy as np


def separator(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}\n")


def main() -> None:
    # ------------------------------------------------------------------
    # 1. Initialize the engine with default configuration
    # ------------------------------------------------------------------
    separator("1. INITIALIZE H11-CGA ENGINE")

    engine = CyberGenesisEngine()
    print("Engine initialized with default configuration.")
    print(f"  Security dimensions: {NUM_DIMENSIONS}")
    print(f"  Dimensions: {', '.join(DIMENSION_NAMES)}")

    # ------------------------------------------------------------------
    # 2. Run nominal state - No threats
    # ------------------------------------------------------------------
    separator("2. NOMINAL STATE - No threats")

    assessment = engine.process_tick()
    print(f"  Status:          {assessment.status.value}")
    print(f"  Genesis Value:   {assessment.genesis_value:.4f}")
    print(f"  Permission:      {assessment.permission}")
    print(f"  DR (divergence): {assessment.dr_value:.4f}")
    print(f"  HSA Zone:        {assessment.hsa_zone.value}")
    print(f"  HSA Coordinate:  {assessment.hsa_coordinate:.4f}")
    print(f"  Security Buffer: {assessment.security_buffer:.4f}")
    print(f"  CCI:             {assessment.cci_value:.4f}")
    print(f"  Limit Util:      {assessment.limit_utilization:.4f}")

    # ------------------------------------------------------------------
    # 3. Inject a moderate identity compromise
    # ------------------------------------------------------------------
    separator("3. IDENTITY COMPROMISE - Severity 0.4")

    assessment = engine.inject_attack("identity_compromise", severity=0.4)
    print(f"  Status:          {assessment.status.value}")
    print(f"  Genesis Value:   {assessment.genesis_value:.4f}")
    print(f"  DR (divergence): {assessment.dr_value:.4f}")
    print(f"  DR adjusted:     {assessment.dr_adjusted:.4f}")
    print(f"  DR rate:         {assessment.dr_rate:.4f}")
    print(f"  HSA Zone:        {assessment.hsa_zone.value}")
    print(f"  HSA Coordinate:  {assessment.hsa_coordinate:.4f}")
    print(f"  CCI:             {assessment.cci_value:.4f}")
    print(f"  CCI Subcritical: {assessment.cci_subcritical}")

    print("\n  State Vector:")
    for i, name in enumerate(DIMENSION_NAMES):
        val = assessment.current_state[i]
        bar = "#" * int(val * 30) + "-" * (30 - int(val * 30))
        print(f"    {name:15s} [{bar}] {val:.3f}")

    if assessment.recommended_actions:
        print(f"\n  Recommended Actions ({len(assessment.recommended_actions)}):")
        for action in assessment.recommended_actions[:5]:
            print(
                f"    -> [{action.urgency.value:8s}] "
                f"{action.action_type.value:20s} "
                f"target={action.target}"
            )

    # ------------------------------------------------------------------
    # 4. Inject a severe privilege escalation (cascade scenario)
    # ------------------------------------------------------------------
    separator("4. PRIVILEGE ESCALATION - Severity 0.7")

    assessment = engine.inject_attack("privilege_escalation", severity=0.7)
    print(f"  Status:          {assessment.status.value}")
    print(f"  Genesis Value:   {assessment.genesis_value:.4f}")
    print(f"  DR (divergence): {assessment.dr_value:.4f}")
    print(f"  HSA Zone:        {assessment.hsa_zone.value}")
    print(f"  CCI:             {assessment.cci_value:.4f}")
    print(f"  CCI Subcritical: {assessment.cci_subcritical}")

    print("\n  State Vector:")
    for i, name in enumerate(DIMENSION_NAMES):
        val = assessment.current_state[i]
        bar = "#" * int(val * 30) + "-" * (30 - int(val * 30))
        print(f"    {name:15s} [{bar}] {val:.3f}")

    if assessment.recommended_actions:
        print(f"\n  Recommended Actions ({len(assessment.recommended_actions)}):")
        for action in assessment.recommended_actions[:5]:
            print(
                f"    -> [{action.urgency.value:8s}] "
                f"{action.action_type.value:20s} "
                f"target={action.target}"
            )

    # ------------------------------------------------------------------
    # 5. View the Genesis Equation term breakdown
    # ------------------------------------------------------------------
    separator("5. GENESIS EQUATION BREAKDOWN")

    print("  G_c(t) = Pi_c * [1 - alpha*DR_c^(a) - beta*|DR_dot| - gamma*H_c+ - delta*CCI/Theta]")
    print()
    for term, value in assessment.genesis_terms.items():
        print(f"    {term:30s} = {value:+.4f}")
    print(f"    {'-' * 42}")
    print(f"    {'G_c(t)':30s} = {assessment.genesis_value:+.4f}")

    # ------------------------------------------------------------------
    # 6. View the transformation matrix strengths
    # ------------------------------------------------------------------
    separator("6. TRANSFORMATION MATRIX - Strongest Couplings")

    tmatrix = engine.get_transformation_matrix()
    src, tgt, val = tmatrix.get_strongest_coupling()
    print(f"  Strongest coupling: {src} -> {tgt} = {val:.2f}")

    vuln_dim, vuln_val = tmatrix.get_most_vulnerable_dimension()
    print(f"  Most vulnerable:    {vuln_dim} (incoming influence = {vuln_val:.2f})")

    # ------------------------------------------------------------------
    # 7. Recovery - run several nominal ticks
    # ------------------------------------------------------------------
    separator("7. RECOVERY - 5 nominal ticks")

    for i in range(5):
        assessment = engine.process_tick()
        print(
            f"  Tick {i + 1}: "
            f"G_c={assessment.genesis_value:+.4f}  "
            f"DR={assessment.dr_value:.4f}  "
            f"HSA={assessment.hsa_coordinate:+.4f}  "
            f"Status={assessment.status.value}"
        )

    # ------------------------------------------------------------------
    # 8. Dashboard snapshot
    # ------------------------------------------------------------------
    separator("8. FINAL DASHBOARD")

    dashboard = engine.get_dashboard()
    for key, value in dashboard.items():
        if isinstance(value, float):
            print(f"    {key:30s}: {value:.4f}")
        else:
            print(f"    {key:30s}: {value}")

    print("\n* H11-CGA basic usage complete.")


if __name__ == "__main__":
    main()
