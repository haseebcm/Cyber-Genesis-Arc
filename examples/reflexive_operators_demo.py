"""
H¹¹-CGA 3.0 — Reflexive Operator Demonstration
===============================================

Shows the architecture inspecting its own model:

1. Ψ_c  — attributing a divergence pattern to the dimension that caused it
2. Λ_c  — grading T_c's prediction against what the state actually did
3. K_c  — pricing the blind spot each nullification would buy
4. Permission debt — withholding trust until the system has stayed clean
"""

import numpy as np

from h11_cga import (
    CyberGenesisEngine,
    CGAConfig,
    TelemetryInput,
    DIMENSION_NAMES,
)


def part_one_origin_attribution() -> None:
    print("=" * 78)
    print("[1] PSI_c -- ORIGIN ATTRIBUTION")
    print("=" * 78)
    print("Each attack perturbs several dimensions. Psi_c runs T_c backwards to")
    print("find which single dimension best explains the whole pattern.\n")

    for attack in ("identity_compromise", "ransomware", "ddos", "supply_chain"):
        engine = CyberGenesisEngine()
        engine.process_tick()
        assessment = engine.inject_attack(attack, severity=0.6)

        ranked = ", ".join(
            f"{h.name} ({h.score:.2f})" for h in assessment.origin_hypotheses
        )
        print(f"  {attack:22s} -> {ranked}")
    print()


def part_two_coherence() -> None:
    print("=" * 78)
    print("[2] LAMBDA_c -- CASCADE COHERENCE")
    print("=" * 78)
    print("T_c predicts where the state moves next. Lambda_c grades that prediction")
    print("on the following tick. An attack is motion the model never claimed.\n")

    engine = CyberGenesisEngine()
    for _ in range(3):
        quiet = engine.process_tick()
        print(f"  quiet tick        coherence = {quiet.coherence:.3f}")

    attacked = engine.inject_attack("zero_day", severity=0.7)
    worst = int(np.argmax(np.abs(attacked.unexplained_vector)))
    print(f"  zero-day injected coherence = {attacked.coherence:.3f}"
          f"   <-- unexplained at {DIMENSION_NAMES[worst]}")
    print()


def part_three_scope_cost() -> None:
    print("=" * 78)
    print("[3] K_c -- SCOPE COST")
    print("=" * 78)
    print("Nullifying a quiet dimension is not free if it feeds live domains.")
    print("K_c prices the blind spot before it is bought.\n")

    engine = CyberGenesisEngine()
    engine.process_tick()
    assessment = engine.inject_attack("identity_compromise", severity=0.6)

    priced = sorted(
        ((DIMENSION_NAMES[i], assessment.nullification_cost[i]) for i in range(11)),
        key=lambda pair: pair[1],
        reverse=True,
    )
    for name, cost in priced[:5]:
        verdict = "expensive to blind" if cost > 0.1 else "cheap to drop"
        print(f"  {name:15s} K = {cost:.4f}   {verdict}")
    print()


def part_four_permission_debt() -> None:
    print("=" * 78)
    print("[4] PERMISSION DEBT")
    print("=" * 78)
    print("Without debt, Pi_c snaps back the instant conditions clear. With it,")
    print("the system must stay clean long enough to earn trust again.\n")

    config = CGAConfig(
        permission_debt_accrual=1.0,
        permission_debt_repayment=1.0,
        permission_debt_max=3.0,
    )
    engine = CyberGenesisEngine(config)
    engine.process_tick()
    engine.inject_attack("data_exfiltration", severity=0.4)

    for tick in range(6):
        assessment = engine.process_tick()
        gate = "GRANTED " if assessment.permission == 1.0 else "WITHHELD"
        print(f"  recovery tick {tick + 1}   debt = {assessment.permission_debt:.2f}"
              f"   Pi_c = {gate}   status = {assessment.status.value}")
    print()


def part_five_model_correction() -> None:
    print("=" * 78)
    print("[5] T_c SELF-CORRECTION (opt-in)")

    print("=" * 78)
    print("When a live host keeps moving in ways the authored coupling does not")
    print("predict, T_c can descend its own prediction error.\n")

    config = CGAConfig(coupling_adaptation_rate=0.05)
    engine = CyberGenesisEngine(config)
    before = engine.get_transformation_matrix().as_array()

    engine.process_tick(TelemetryInput(raw_values={"compute": 0.55}))
    engine.process_tick(TelemetryInput(raw_values={"memory": 0.35}))
    engine.process_tick(TelemetryInput(raw_values={"data": 0.40}))

    after = engine.get_transformation_matrix().as_array()
    drift = np.abs(after - before)
    i, j = np.unravel_index(int(np.argmax(drift)), drift.shape)

    print(f"  largest revision: {DIMENSION_NAMES[i]} -> {DIMENSION_NAMES[j]}")
    print(f"    authored {before[i, j]:.4f}   corrected {after[i, j]:.4f}")
    print(f"  total coupling drift: {float(np.sum(drift)):.4f}")
    print("  (disabled by default: the authored matrix encodes intent)")
    print()


def main() -> None:
    print()
    part_one_origin_attribution()
    part_two_coherence()
    part_three_scope_cost()
    part_four_permission_debt()
    part_five_model_correction()
    print("=" * 78)


if __name__ == "__main__":
    main()
