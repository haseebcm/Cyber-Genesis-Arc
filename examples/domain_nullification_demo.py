"""
H¹¹-CGA Domain Nullification Demo
===================================

Demonstrates the Domain Nullification Principle:
  "Activate what matters + Suppress what does not"

Shows how selectively nullifying irrelevant security domains
reduces the effective attack surface and changes the DR computation.
"""

from h11_cga import (
    CyberGenesisEngine,
    DomainVector,
    DIMENSION_NAMES,
    NUM_DIMENSIONS,
)
import numpy as np


def print_domain_status(engine: CyberGenesisEngine, label: str) -> None:
    """Print current domain activations and their effect."""
    a = engine.process_tick()

    print(f"\n  -- {label} --")
    print(f"  G_c = {a.genesis_value:+.4f}  DR = {a.dr_value:.4f}  "
          f"DR_adj = {a.dr_adjusted:.4f}  W_c(a) = {a.domain_metric:.4f}")

    dv = a.domain_vector
    print(f"  Domain activations:")
    for i, name in enumerate(DIMENSION_NAMES):
        level = dv.activations[i]
        if level == 0:
            status = "  [XX] NULLIFIED"
        elif level < 0.5:
            status = f"  [--] REDUCED ({level:.1f})"
        elif level < 1.0:
            status = f"  [..] PARTIAL ({level:.1f})"
        else:
            status = "  [OK] ACTIVE"
        print(f"    {name:15s}{status}")

    print(f"  Active: {len(dv.active_domains)}/{NUM_DIMENSIONS}  "
          f"Complexity ratio: {dv.complexity_ratio:.2f}")


def main() -> None:
    print("=" * 70)
    print("  H11-CGA DOMAIN NULLIFICATION DEMONSTRATION")
    print("=" * 70)

    # ------------------------------------------------------------------
    # 1. All domains active — full attack surface
    # ------------------------------------------------------------------
    engine = CyberGenesisEngine()

    # Inject a moderate threat
    engine.inject_attack("identity_compromise", severity=0.4)
    print_domain_status(engine, "ALL DOMAINS ACTIVE (full surface)")

    # ------------------------------------------------------------------
    # 2. Nullify irrelevant domains for a pure-IT environment
    # ------------------------------------------------------------------
    print("\n" + "-" * 70)
    print("  Scenario: Pure IT environment - no OT/industrial concerns")
    print("-" * 70)

    engine2 = CyberGenesisEngine()
    engine2.inject_attack("identity_compromise", severity=0.4)

    # Nullify domains not relevant to this IT environment
    engine2.set_domain_activation("resource", 0.3)
    engine2.set_domain_activation("recovery", 0.5)

    print_domain_status(engine2, "SELECTIVE NULLIFICATION (IT-focused)")

    # ------------------------------------------------------------------
    # 3. Aggressive nullification — minimal surface
    # ------------------------------------------------------------------
    print("\n" + "-" * 70)
    print("  Scenario: Focus only on the compromised dimensions")
    print("-" * 70)

    engine3 = CyberGenesisEngine()
    engine3.inject_attack("identity_compromise", severity=0.4)

    # Only keep Identity, Authorization, Trust active (the affected chain)
    for dim in DIMENSION_NAMES:
        if dim.lower() not in ("identity", "authorization", "trust"):
            engine3.set_domain_activation(dim, 0.0)

    print_domain_status(engine3, "AGGRESSIVE NULLIFICATION (3 domains)")

    # ------------------------------------------------------------------
    # 4. Compare DR values across configurations
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  COMPARISON SUMMARY")
    print("=" * 70)

    print(f"\n  {'Configuration':35s} {'Active':>8s} {'W_c(a)':>8s} {'Effect':>20s}")
    print(f"  {'-' * 73}")
    print(f"  {'Full attack surface':35s} {'11':>8s} {'1.00':>8s} {'Maximum exposure':>20s}")
    print(f"  {'IT-focused reduction':35s} {'~9':>8s} {'~0.85':>8s} {'Reduced surface':>20s}")
    print(f"  {'Targeted 3-domain':35s} {'3':>8s} {'~0.27':>8s} {'Minimal exposure':>20s}")

    print(f"\n  Key insight: Domain Nullification reduces DR_c^(a) = W_c(a) * DR_c")
    print(f"  By nullifying irrelevant domains, the effective divergence decreases")
    print(f"  even though the raw divergence (DR_c) stays the same.\n")

    # ------------------------------------------------------------------
    # 5. The Nullification Principle
    # ------------------------------------------------------------------
    print("=" * 70)
    print("  H11 SECURITY NULLIFICATION PRINCIPLE")
    print("=" * 70)
    print()
    print("  A security system should not require successful identification")
    print("  of every malicious object if unauthorized states can be prevented")
    print("  from acquiring execution authority.")
    print()
    print("  Unauthorized != Execute")
    print("  Instead: Unauthorized -> Null")
    print()
    print("  Complexity does not necessarily grow with universality:")
    print("  More Domains -> Selective Activation -> Nullification -> Bounded Complexity")
    print()

    print("* Domain Nullification demo complete.\n")


if __name__ == "__main__":
    main()
