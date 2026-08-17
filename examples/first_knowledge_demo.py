"""
H11-CGA 4.0 -- First Knowledge Demonstration
=============================================

The 11 dimensions were never an engineering choice. They are the 11 Universal
Laws, and this layer measures the architecture against the derivative condition
each Law imposes.

Five things are shown:

  1. Phi_0    the Origin Flux, and what it detects that DR_c cannot
  2. S_ig     the Sovereign Signature, and why it is not Lambda_c
  3. Law 8    whether dCR's effort is actually aimed at the damage
  4. Phi_H11  the Golden Ratio restated as closure of the arc
  5. Authority   what changes when a broken Law is allowed to refuse existence
"""

import numpy as np

from h11_cga import (
    CyberGenesisEngine,
    CGAConfig,
    SecurityState,
    SecurityBaseline,
    OriginFlux,
    SovereignSignature,
    NUM_DIMENSIONS,
    DIMENSION_INDEX,
)


def rule(title: str) -> None:
    print()
    print("=" * 78)
    print(f"  {title}")
    print("=" * 78)


def state(vector) -> SecurityState:
    return SecurityState(vector=np.asarray(vector, dtype=np.float64))


# ---------------------------------------------------------------------------
# 1. Phi_0 -- the Origin Flux
# ---------------------------------------------------------------------------

def demo_origin_flux() -> None:
    rule("1. Phi_0 -- Origin Flux (Law 1)")
    print("  Phi_0 = integral[S_data] * G_H11 / Identity_z")
    print()
    print("  Identity_z sits in the denominator, so Phi_0 measures whether the")
    print("  system has grown composite relative to the root anchoring it.")
    print()

    flux = OriginFlux()
    baseline = SecurityBaseline(reference=np.ones(NUM_DIMENSIONS))

    nominal = np.ones(NUM_DIMENSIONS)

    faded = np.full(NUM_DIMENSIONS, 0.4)

    compromised = np.ones(NUM_DIMENSIONS)
    compromised[DIMENSION_INDEX["identity"]] = 0.4

    dissolved = np.ones(NUM_DIMENSIONS)
    dissolved[DIMENSION_INDEX["identity"]] = 0.0

    for label, vector, governance in [
        ("at the root", nominal, 1.0),
        ("faded evenly to 0.4", faded, 1.0),
        ("identity compromised", compromised, 1.0),
        ("governance nullified", nominal, 0.0),
        ("identity destroyed", dissolved, 1.0),
    ]:
        phi_0, defined = flux.compute(state(vector), baseline, governance)
        if not defined:
            reading = "UNDEFINED -- no root left to exist from"
        elif phi_0 == 0.0:
            reading = "0.0000    -- G_H11 became the nullifier"
        else:
            verdict = "Escalation" if phi_0 > 1.001 else (
                "Decay" if phi_0 < 0.999 else "Stasis"
            )
            reading = f"{phi_0:.4f}    -- {verdict}"
        print(f"    {label:24s} Phi_0 = {reading}")

    print()
    print("  Note the second row. Uniform decay leaves Phi_0 untouched, because")
    print("  the 1st Law measures proportion, not magnitude -- that is DR_c's job.")
    print("  What it does catch is the third row: an intact-looking state whose")
    print("  identity anchor has been cut out from under it.")


# ---------------------------------------------------------------------------
# 2. S_ig is not Lambda_c
# ---------------------------------------------------------------------------

def demo_signature() -> None:
    rule("2. S_ig -- Sovereign Signature (and why it is not Lambda_c)")
    print("  Lambda_c, added in 3.0, asks whether T_c predicted the motion.")
    print("  S_ig asks whether the system still has the shape of its root.")
    print("  A perfectly predicted collapse scores high on one and low on the other.")
    print()

    baseline = SecurityBaseline(reference=np.ones(NUM_DIMENSIONS))

    uniform = np.full(NUM_DIMENSIONS, 10.0 / NUM_DIMENSIONS)
    targeted = np.ones(NUM_DIMENSIONS)
    targeted[DIMENSION_INDEX["data"]] = 0.0

    print(f"    Both states have carried away the same total magnitude "
          f"({np.sum(uniform):.2f} of {NUM_DIMENSIONS}).")
    print()
    for label, vector in [("uniform decay", uniform), ("data dimension lost", targeted)]:
        sig = SovereignSignature().compute(state(vector), baseline)
        reading = "form preserved" if sig > 0.999 else "form altered -- mutation"
        print(f"    {label:24s} S_ig = {sig:.4f}  -- {reading}")

    print()
    print("  Equal damage, different verdicts. Decay and mutation are not the")
    print("  same failure, and Law 10 refuses to call the second one evolution.")


# ---------------------------------------------------------------------------
# 3. Law 8 -- is the response aimed at anything?
# ---------------------------------------------------------------------------

def demo_action_alignment() -> None:
    rule("3. Law 8 -- Action: is dCR aimed at the actual damage?")
    print("  A = d/dt(S_ig * Phi_0) * cos(theta)")
    print()
    print("  The framework is explicit that action against the grain does no")
    print("  work. Law 8 turns that into an audit of dCR itself, which nothing")
    print("  in the architecture had ever performed.")
    print()

    engine = CyberGenesisEngine()
    assessment = engine.inject_attack("ransomware", severity=0.45)
    law8 = assessment.law_conformance.laws[7]

    print(f"    dCR proposed {len(assessment.recommended_actions)} action(s):")
    for action in assessment.recommended_actions[:5]:
        print(f"      -> [{action.urgency.value:8s}] {action.action_type.value:12s} "
              f"target={action.target}")

    print()
    print(f"    cos(theta) = {law8.measured:.4f}  -> {law8.verdict.value}")
    print(f"    Effort landing on the deficit: {law8.measured:.1%}")


# ---------------------------------------------------------------------------
# 4. Phi_H11 -- closing the arc
# ---------------------------------------------------------------------------

def demo_golden_ratio() -> None:
    rule("4. Phi_H11 -- the Golden Ratio as closure, not a decimal")
    print("  Phi_H11 = Law_11 (Resolution) / Law_1 (Origin)")
    print()
    print("  Perfect proportion is reached when the End matches the Beginning.")
    print("  Watch it open as an attack drives Resolution away from Origin.")
    print()

    engine = CyberGenesisEngine()
    print("    tick  event                 Phi_0     S_ig    Phi_H11   sovereign")
    print("    " + "-" * 66)

    for tick in range(1, 9):
        if tick == 4:
            assessment = engine.inject_attack("supply_chain", severity=0.35)
            event = "supply_chain attack"
        else:
            assessment = engine.process_tick()
            event = "steady"

        report = assessment.law_conformance
        phi = report.phi_h11
        phi_text = "   inf" if phi == float("inf") else f"{phi:6.3f}"
        print(f"    {tick:>4}  {event:20s} {report.origin_flux:6.4f}  "
              f"{report.sovereign_signature:6.4f}   {phi_text}   "
              f"{'yes' if report.sovereign else 'NO'}")


# ---------------------------------------------------------------------------
# 5. Authority
# ---------------------------------------------------------------------------

def demo_authority() -> None:
    rule("5. Authority -- what a broken Law is allowed to do")
    print("  'If the data does not comply with the Laws, G_H11 becomes a")
    print("   nullifier (0), preventing existence.'")
    print()
    print("  Taken literally that hands Pi_c to eleven invariants at once, so it")
    print("  ships off. Here is the same attack under both settings.")
    print()

    for label, config in [
        ("advisory (default)", CGAConfig()),
        ("law_authoritative=True", CGAConfig(law_authoritative=True)),
    ]:
        engine = CyberGenesisEngine(config)
        assessment = engine.inject_attack("identity_compromise", severity=0.2)
        broken = [law.law for law in assessment.law_conformance.violated]

        print(f"    {label:24s} Pi_c={assessment.permission:.0f}  "
              f"status={assessment.status.value:11s} laws broken={broken}")

    print()
    print("  Same state, same Law reading. Only the consequence differs.")


def main() -> None:
    print()
    print("#" * 78)
    print("#  H11 CYBER GENESIS ARCHITECTURE 4.0 -- FIRST KNOWLEDGE")
    print("#  The 11 dimensions are the 11 Universal Laws.")
    print("#" * 78)

    demo_origin_flux()
    demo_signature()
    demo_action_alignment()
    demo_golden_ratio()
    demo_authority()

    print()
    print("=" * 78)
    print("  Demonstration complete.")
    print("=" * 78)
    print()


if __name__ == "__main__":
    main()
