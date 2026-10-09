# H¹¹ Cyber Genesis Architecture (H¹¹-CGA)

[![Author: Mohamed Haseeb C M](https://img.shields.io/badge/author-Mohamed%20Haseeb%20C%20M-blue.svg)](https://github.com/haseebcm)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Architecture: 4.0](https://img.shields.io/badge/architecture-4.2--HARDENED-purple.svg)](#foundation-the-11-universal-laws)

> **Created & Designed by Mohamed Haseeb C M**
>
> A cybersecurity architecture in which a digital system is represented as a continuously
> measured 11-dimensional security state, governed by the 11 Universal Laws of the
> **H¹¹ First Knowledge** framework. Divergence from an authorized root is quantified,
> progression toward structural limits is evaluated, irrelevant domains are nullified,
> high-risk states are converged, and execution is permitted only where the Laws are satisfied.

---

## Windows response release 4.2

See [Windows installation and real response instructions](docs/WINDOWS.md). Version 4.2 adds actual user-process suspension/resumption, authenticated operator controls, a durable SQLite journal, and an independent rollback watchdog. The live response example verifies a real heartbeat stopping and resuming.

See [deployment and presentation instructions](docs/DEPLOYMENT.md) for an offline demo and secure deployment. The H11 model is preserved; the runtime now isolates proposal scoring, bounds histories, validates inputs, requires registered tool policies, and secures server defaults.

```bash
h11-server --demo  # isolated simulation dashboard on loopback
h11-server         # read-only host monitoring with baseline calibration
```

Remote binding requires `H11_API_TOKEN`. Simulation controls are disabled in monitor mode. Dashboard reads use cached assessments and never advance the model. This release is hardened for demonstrations and controlled pilots; incident efficacy and real remediation still require external validation.

## Contents

- [What this is](#what-this-is)
- [Foundation: the 11 Universal Laws](#foundation-the-11-universal-laws)
- [The Cyber Genesis Equation](#the-cyber-genesis-equation)
- [The 11-dimensional state space](#the-11-dimensional-state-space)
- [The control loop](#the-control-loop)
- [Operator reference](#operator-reference)
  - [Core operators](#core-operators)
  - [Reflexive operators](#reflexive-operators)
  - [Law operators](#law-operators)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Telemetry and live monitoring](#telemetry-and-live-monitoring)
- [AI agent guardrails](#ai-agent-guardrails)
- [Control plane](#control-plane)
- [Configuration](#configuration)
- [Implementation status](#implementation-status)
- [Project structure](#project-structure)
- [Examples and tests](#examples-and-tests)

---

## What this is

A cyber system is **not** treated here as a collection of devices, signatures, firewalls
and alerts. It is represented as a continuously changing security state, measured for
divergence from its own authorized root, evaluated against its structural limits, and
forced toward a governed state.

```
Traditional:  ATTACK → SIGNATURE → ALERT → ANALYST → RESPONSE
H¹¹-CGA:      STATE → DIVERGENCE → LIMIT → NULLIFICATION → CONVERGENCE → REGENERATION
```

| Aspect | Traditional | H¹¹-CGA |
|--------|------------|---------|
| Threat model | Binary — attack or no attack | Continuous state trajectory |
| Detection | Signatures and rules | Divergence from a learned root |
| Measurement | Alert count | Distance to structural failure |
| Response | Analyst-driven | ΔCR-prioritized convergence |
| Domains | Separate tools | Unified, and nullifiable |
| Architecture | Open loop — detect, alert, respond | Closed loop — state, converge, rebaseline |
| Identity | Static credential | Dynamic state function |
| Thresholds | Fixed | Adaptive |

Security sits **upstream of execution**. Nothing runs merely because it exists.

---

## Foundation: the 11 Universal Laws

The eleven dimensions are not an engineering choice, and this architecture is not an
application of control theory. H¹¹-CGA is a cyber instantiation of the **H¹¹ First
Knowledge** framework, in which existence is governed by 11 Universal Laws. Each Law
carries a derivative condition and a value that condition must hold, which is what makes
the framework testable rather than descriptive.

| # | Law | Derivative condition | Failure reads as |
|---|-----|---------------------|------------------|
| 1 | Origin | $d\mathcal{E}/dO = 1$ | above unity Escalation, below unity Decay |
| 2 | Creation | $d^2\mathcal{E}/dO^2 = 0$ | acceleration away from the blueprint |
| 3 | Existence | $d\text{Ex}/dt = 0$ | negative is dying, positive is runaway |
| 4 | Boundary | $d\Sigma/dV$ finite | an infinity is a failed calculation |
| 5 | Constraint | $d\Omega/dt \approx 0$ | work capacity is not steady |
| 6 | Limit | $\lim_{\mathcal{E} \to L} d\mathcal{E}/dt = 0$ | still changing at the ceiling |
| 7 | Relation | $dS_1/d\mathcal{R} \to 0$ | interaction destroying its participants |
| 8 | Action | energy minimal at alignment | work performed against the grain |
| 9 | Balance | $d^2\mathcal{B}/dt^2 \to 0$ | the system will not return to centre |
| 10 | Evolution | $d\text{Origin}/d\text{Evolution} = 1$ | change that did not preserve the signature |
| 11 | Resolution | $\mathcal{R}_s \to 1$ | resolving violently rather than cleanly |

The framework groups these as **Seed** (1–3), **Vessel** (4–6), **Interaction** (7–9)
and **Return** (10–11).

Much of the architecture was implementing the Laws before they were made explicit:

- **Π_c** is Law 1's moment at which a variable is *permitted to move from Incoherence
  into Intelligibility*.
- **Domain Nullification** is $\mathcal{G}_{H11}$ becoming the nullifier that refuses
  what does not comply.
- **ULE** is Laws 5 and 6; **Encrypt-IC's boundary** is Law 4; **CONVERGE** is Law 11's
  point of convergence.
- **DSA's** `ESCALATING` / `RECOVERING` / `NORMAL` split is Law 1's own verdict.

The Law layer measures all eleven conditions every tick. See
[Law operators](#law-operators).

---

## The Cyber Genesis Equation

The master equation governing the architecture:

$$G_c(t) = \Pi_c(t)\left[1 - \alpha \cdot DR_c^{(a)}(t) - \beta \cdot \dot{DR}_c^{(a)}(t) - \gamma \cdot H_c^+(t) - \delta \cdot \frac{CCI_c(t)}{\Theta_c}\right]$$

| Term | Meaning |
|------|---------|
| $\Pi_c$ | Genesis permission operator — 0 or 1 |
| $DR_c^{(a)}$ | Domain-adjusted divergence ratio |
| $\dot{DR}_c^{(a)}$ | Divergence acceleration |
| $H_c^+$ | HSA singularity coordinate, positive part |
| $CCI_c / \Theta_c$ | Normalized cascade collapse index |

**Convergent Permission Principle** — the safety condition for continued execution:

$$\text{Continuation} \iff \Pi_c = 1 \land H_c < 0 \land CCI_c < \Theta_c \land DR_c^{(a)} \to 0$$

$G_c$ maps to a discrete status: `PERMITTED`, `MONITORING`, `WARNING`, `CRITICAL`,
`CONTAINMENT`, `EMERGENCY`.

---

## The 11-dimensional state space

Every system is a state vector $X_c(t) \in [0,1]^{11}$, where 1 is fully nominal and
0 is fully compromised.

| Dim | Name | Description |
|-----|------|-------------|
| 0 | **Identity** | Identity integrity — also supplies $\text{Identity}_z$ to Law 1 |
| 1 | **Authorization** | Authorization state |
| 2 | **Network** | Network state |
| 3 | **Data** | Data state |
| 4 | **Compute** | Compute state |
| 5 | **Memory** | Memory and process state |
| 6 | **Execution** | Execution state |
| 7 | **Resource** | Resource consumption |
| 8 | **Trust** | Trust state |
| 9 | **Governance** | Domain and governance state |
| 10 | **Recovery** | Recovery and integrity state |

The **11×11 transformation matrix** $T_c$ holds 121 influence nodes and is indexed
`[source, target]`, so influence flows along columns and a cascade increment is
$T_c^{\top}p$. $T_c$ is authored and deterministic; every operator that reasons about
propagation — CCI, Ψ_c, Λ_c, Law 7, Law 9 — shares the same matrix.

---

## The control loop

```
         ┌───────────────────────────────────────┐
         │                                       │
         ▼                                       │
    ┌─────────┐    ┌──────────┐    ┌──────────┐  │
    │  SENSE  │───>│ DIVERGE  │───>│  LIMIT   │  │
    └─────────┘    └──────────┘    └──────────┘  │
                                        │        │
                                        ▼        │
    ┌─────────┐    ┌──────────┐    ┌──────────┐  │
    │ RE-EVAL │<───│ ENCRYPT  │<───│ CONVERGE │  │
    └────┬────┘    └──────────┘    └──────────┘  │
         │                                       │
         └───────────────────────────────────────┘
```

| Engine | Full name | Role |
|--------|-----------|------|
| **SENSE** | Security State & Environment Normalization | MCC and telemetry into the state vector |
| **DIVERGE** | Cyber Divergence Intelligence | DSA and DR into a behavioural trajectory |
| **LIMIT** | Universal Cyber Boundary | ULE and HSA into distance-to-failure |
| **CONVERGE** | Adaptive Cyber Response | CCI and ΔCR into prioritized actions |
| **ENCRYPT-IC** | Adaptive Security Boundary | Genesis and nullification into boundary enforcement |

One call to `process_tick()` runs a full cycle. **RE-EVAL** closes the loop: residual
divergence propagates through $T_c$, ΔCR actions pull degraded dimensions back toward
$X_c^*$, and `R_genesis` regenerates when the system is recovering inside a controlled
zone. The result feeds the next SENSE.

---

## Operator reference

### Core operators

| Operator | Symbol | Question it answers |
|----------|--------|--------------------|
| Genesis permission | Π_c | Is this state permitted to exist? |
| Divergence ratio | DR_c | How far is the state from its root? |
| Singularity approach | H_c | How much buffer remains before the boundary? |
| Universal limit engine | Ω_s | How much structural capacity is consumed? |
| Cascade collapse index | CCI_c | Will damage here bring down the rest? |
| Domain nullification | W_c(a) | Which domains are we still evaluating? |
| Dynamic cyber response | ΔCR | What should be done first? |

### Reflexive operators

These turn the architecture back on its own model. Each is derived from quantities
already computed; no external estimator is introduced.

| Operator | Symbol | Question it answers |
|----------|--------|--------------------|
| `OriginTracer` | Ψ_c | The divergence looks like *this* — which dimension started it? |
| `CoherenceAuditor` | Λ_c | $T_c$ claimed the state would move *there*. Did it? |
| Scope cost | K_c | If I nullify this domain, what do I stop being able to see? |
| Permission debt | — | Π_c just denied. How long must the system stay clean? |

**Ψ_c — origin attribution.** CCI runs $T_c$ forwards: given damage here, where does it
spread? Ψ_c runs the same matrix backwards. For each dimension it builds the cascade
signature that dimension would produce if hit alone,

$$s_i = \sum_{h=0}^{d} \lambda^h (T_c^{\top})^h u_i$$

then ranks signatures by alignment with the divergence actually measured. The coupling
matrix becomes an attribution instrument without a second model of the system.

```python
assessment = engine.inject_attack("ransomware", severity=0.6)
for h in assessment.origin_hypotheses:
    print(h.name, round(h.score, 3))
# Data 0.735
# Execution 0.663
# Recovery 0.627
```

**Λ_c — cascade coherence.** Each tick $T_c$ makes an implicit prediction about where the
state moves next, and nothing ever checked it. Λ_c records the prediction and grades it
on the following tick:

$$\Lambda_c = 1 - \frac{\lVert x_{\text{actual}} - x_{\text{pred}} \rVert}{\lVert x_{\text{actual}} - x_{\text{prev}} \rVert + \lVert x_{\text{actual}} - x_{\text{pred}} \rVert}$$

A score of 1.0 means the coupling model explained the motion exactly, 0.5 means it
predicted stillness and the system moved anyway, and below 0.5 means it predicted the
wrong direction. **Low coherence is a signal in its own right**, independent of
divergence magnitude, because it marks behaviour the architecture cannot account for.

The per-dimension miss also says *where* the model was wrong, which is enough to correct
the coupling that produced it. Setting `coupling_adaptation_rate > 0` lets $T_c$ descend
its own prediction error, $\Delta T_c[i,j] = \eta \cdot r_i \cdot \text{unexplained}_j$.
Off by default: the authored coupling encodes intent.

**K_c — scope cost.** Quiet is not the same as safe, and a silent dimension feeding live
domains is about to become loud. K_c prices the blind spot before it is bought:

$$K_i = e_i \cdot \Big(1 + \sum_j T_c[i,j] \cdot a_j\Big)$$

A quiet leaf is cheap to stop watching. A quiet hub is not.

**Permission debt.** Π_c is binary and instantaneous, so a state hovering at the envelope
edge makes it oscillate. Setting `permission_debt_accrual > 0` gives the gate hysteresis:
denied ticks accrue debt and trust is withheld until clean ticks repay it. Off by
default, since it changes the semantics of the gate.

### Law operators

The Laws are written in terms of two quantities the architecture did not previously have.

**Φ₀ — the Origin Flux (Law 1).**

$$\Phi_0 = \lim_{\Delta \to 0} \frac{\int [S_{data}] \cdot \mathcal{G}_{H11}}{\text{Identity}_z}$$

The architecture carried the *gate* this Law describes but never the *magnitude*, which
Laws 1, 2, 4, 6, 8 and 11 all divide by or scale against. Every term already existed:
$S_{data}$ is the state held against its own root $X_c(t)/X_c^*$, $\mathcal{G}_{H11}$ is
exactly the domain metric $W_c(a)$, and $\text{Identity}_z$ is the Identity dimension
anchoring the system to its inception. At the nominal root $\Phi_0 = 1$.

Both failure modes the Law names are real and distinct. **Φ₀ = 0** is refusal —
governance nullified the data. **Φ₀ undefined** is dissolution — $\text{Identity}_z$
vanished and there is no root left to exist from. Existence requires $0 < \Phi_0 < \infty$.

Because $\text{Identity}_z$ is the denominator, Φ₀ measures *proportion* and is invariant
to uniform scale. That is the Law's own structure rather than a defect, and it is why the
source speaks of keeping a system unique and non-composite instead of measuring health.
A system fading evenly holds Φ₀ steady and is caught by DR_c; what Φ₀ catches is an
intact-looking state whose identity anchor has been cut out from under it, which drives
it *above* unity into Escalation.

**S_ig — the Sovereign Signature.** The Coherence Factor: how closely the system still
reflects its Originator. It carries Laws 3, 4, 8, 9 and 10, and **it is not what Λ_c
measures**. Λ_c grades whether $T_c$ predicted the state's motion, which is an audit of
the model; S_ig asks whether the system still has the shape of the thing it was
calibrated to be. The two are deliberately independent, and a perfectly predicted
collapse scores high on Λ_c and low on S_ig.

Measured as the alignment of $X_c(t)$ with $X_c^*$, S_ig captures form rather than
magnitude, which is what separates decay from mutation: uniform loss preserves the
signature, targeted loss destroys it, and Law 10 refuses to call the second one evolution.

**Λ₁₁ — the conformance vector.** Each Law is scored by how far its measured derivative
sits from the value it requires, giving `conformance = 1/(1 + violation)`. These are
system-wide invariants over the whole state, not labels bound to individual dimensions;
only Law 1 names one, taking Identity as its denominator. Since the Laws demand exact
values and real telemetry never lands exactly, `law_violation_tolerance` sets the band
that counts as Stasis.

Law 8 is worth singling out. The framework holds that action against the grain does no
work, and turning that into cos(θ) between ΔCR's proposed effort and the actual deficit
yields something the architecture had never done: an audit of whether its own
recommendations point at the damage.

**Φ_H11 — the Golden Ratio as closure.**

$$\Phi_{H11} = \frac{\text{Law}_{11}\ (\text{Resolution})}{\text{Law}_{1}\ (\text{Origin})}$$

The framework rejects the Golden Ratio as a decimal and restates it as an axiom of
alignment: perfect proportion is reached when the End matches the Beginning, closing the
loop with zero waste. It is taken over the two Laws' **measured values**, not their
conformance scores — scoring it on conformance looks natural but is wrong, since two Laws
failing by the same amount divide out to a flawless 1.0 on a system that has already
dissolved.

```python
from h11_cga import CyberGenesisEngine

engine = CyberGenesisEngine()
assessment = engine.inject_attack("identity_compromise", severity=0.2)

print(assessment.origin_flux)          # 1.2000 — data outrunning its anchor
print(assessment.sovereign_signature)  # form fidelity to X_c*
print(assessment.law_conformance.phi_h11)

for law in assessment.law_conformance.violated:
    print(law)   # Law1 Origin: +1.2000 vs +1.0000 -> ESCALATION
```

**Authority.** The source is unambiguous that a violation should bite: *"if the data does
not comply with the Laws, $\mathcal{G}_{H11}$ becomes a nullifier (0), preventing
existence."* Setting `law_authoritative = True` implements exactly that — a broken Law
revokes Π_c and the system drops to `EMERGENCY`.

It ships **off by default**, for the same reason as permission debt and coupling
adaptation: it hands a core gate to eleven invariants at once. Enable it deliberately,
after watching the conformance report against your own workload. Φ₀ and S_ig are cheap
and always measured; only the audit and its authority are optional.

---

## Installation

```bash
git clone https://github.com/haseebcm/Cyber-Genesis-Arc.git
cd Cyber-Genesis-Arc
pip install -e ".[dev]"
```

Requires Python 3.10+. Runtime dependencies are `numpy` and `psutil`.

---

## Quick start

```python
from h11_cga import CyberGenesisEngine

engine = CyberGenesisEngine()

# One full cycle of the control loop at the nominal root
assessment = engine.process_tick()
print(assessment.status.value)      # PERMITTED
print(assessment.genesis_value)     # 1.0000
print(assessment.origin_flux)       # 1.0000

# Inject a cascading privilege escalation
assessment = engine.inject_attack("privilege_escalation", severity=0.8)
print(assessment.status.value)
print(assessment.cci_value, assessment.cci_threshold)

for action in assessment.recommended_actions[:3]:
    print(action.urgency.value, action.action_type.value, action.target)

# Everything from one tick, condensed
print(assessment.summary())
```

Built-in attack patterns: `identity_compromise`, `privilege_escalation`,
`data_exfiltration`, `ddos`, `insider_threat`, `zero_day`, `lateral_movement`,
`ransomware`, `supply_chain`.

---

## Telemetry and live monitoring

The **Virtual Interface Engine (VIE)** adapters in `h11_cga.adapters` normalize real
metrics into the 11-dimensional state vector.

| Adapter | Source | Dimensions it measures |
|---------|--------|------------------------|
| `SystemAdapter` | Host OS via `psutil` | CPU (`Compute`), RAM (`Memory`), swap pressure (`Recovery`), disk capacity (`Resource`), disk I/O rate (`Data`), open sockets (`Network`), processes (`Execution`), active logins (`Identity`) |
| `EBPFNetworkProbe` | Linux kernel counters in `/proc/net/snmp` and `/proc/net/netstat` | SYN-backlog drops and connection failures (`Network`), packet throughput rate (`Resource`). Linux only |
| `KubernetesAdapter` | Cluster metrics | Pod restarts (`Recovery`/`Execution`), API latency (`Governance`), 401/403 rates (`Authorization`), quotas (`Resource`). Requires a `metrics_provider` |
| `LogAdapter` | Syslog, auth and JSON audit trails | Parses SSH failures, root escalations, OOM kills and segfaults into `SecurityEvent` objects |
| `TelemetryIngestionHub` | Multi-source | Averages each dimension only across adapters that measured it, and records provenance |

### Measurement contract

An adapter reports a dimension only if it genuinely measures it. Unmeasured dimensions
are **omitted, never padded** with nominal constants — padding dilutes real signal once
the hub averages across sources. An adapter whose source is unreachable reports
`is_available() == False` and is skipped entirely.

Behavioural dimensions such as `Authorization`, `Trust` and `Governance` have no honest
host-OS metric, so they are driven by event adapters and by propagation through $T_c$.

```python
hub.describe_sources()   # per-adapter MEASURING / SKIPPED status
hub.last_provenance      # {dimension: [adapters that measured it]}
```

### Baseline calibration

A real host never idles at the ideal vector $X_c^* = \mathbf{1}$ — a healthy laptop may
sit at 40% free RAM and 70% disk usage. Scoring divergence against a perfect baseline
condemns normal load as `EMERGENCY`.

The monitor first **observes** the host for a warmup period, sets $X_c^*$ to the observed
mean, and derives the envelope $[L_c, U_c]$ from observed variance. This is the
rebaseline step of the regeneration layer.

Calibration is **off by default**, so simulation and attack injection keep working
against the ideal root.

```bash
h11-monitor                                # continuous host monitoring
h11-monitor --duration 30 --interval 0.5   # bounded run
h11-monitor --calibrate 20                 # learn this host's root first
```

```python
config = CGAConfig(baseline_calibration_ticks=20)
engine = CyberGenesisEngine(config)
engine.is_calibrating              # True until warmup completes
engine.get_calibration_progress()  # (observed, required)
```

---

## AI agent guardrails

`AIAgentGuardrailEngine` intercepts proposed autonomous agent tool calls, projects their
11-dimensional impact before execution, and nullifies to $N_0$ when Π_c refuses.

```python
from h11_cga import AIAgentGuardrailEngine, AIToolRequest, AIToolCategory

guardrail = AIAgentGuardrailEngine()

request = AIToolRequest(
    agent_id="research_agent_01",
    tool_name="privileged_shell",
    category=AIToolCategory.PRIVILEGED_CMD,
    parameters={"command": "sudo rm -rf /root"},
)

decision = guardrail.inspect_and_govern(request)
if not decision.permitted:
    print(f"Intercepted and nullified (N_0): {decision.reason}")
```

`SwarmAIGuardrailEngine` extends this to multi-agent teams, guarding against
agent-to-agent prompt poisoning, recursive subagent spawning, and cross-agent privilege
cascades.

---

## Control plane

A REST API and web dashboard over the live engine state.

```bash
h11-server
```

`GET /api/v1/status` returns the full assessment including `origin_flux`,
`sovereign_signature`, `law_conformance`, `coherence`, `permission_debt` and
`origin_hypotheses`.

---

## Configuration

All behaviour is driven by `CGAConfig`. The defaults are deliberately conservative:
anything that changes the semantics of a core gate ships off.

| Setting | Default | Effect |
|---------|---------|--------|
| `closed_loop_enabled` | `True` | Feed RE-EVAL back into SENSE |
| `origin_trace_enabled` | `True` | Attribute divergence to an origin (Ψ_c) |
| `coherence_enabled` | `True` | Grade $T_c$'s prediction each tick (Λ_c) |
| `nullification_cost_enabled` | `True` | Price blind spots before nullifying (K_c) |
| `law_conformance_enabled` | `True` | Audit all 11 Laws each tick |
| `baseline_calibration_ticks` | `0` | Warmup ticks before divergence is scored |
| `coupling_adaptation_rate` | `0.0` | Let $T_c$ rewrite itself from coherence misses |
| `permission_debt_accrual` | `0.0` | Give Π_c hysteresis after a denial |
| `law_authoritative` | `False` | Let a broken Law revoke Π_c |

---

## Implementation status

This project is an alpha research implementation. The following distinctions matter when
reading results, and are stated here rather than left for you to discover in the source.

**Measured.** The control loop, all core and reflexive operators, the Law layer, Φ₀,
S_ig, Φ_H11, `SystemAdapter`, and `EBPFNetworkProbe` on Linux all compute from real
inputs. The test suite exercises them against constructed states with known answers.

**Modelled, not measured.** $T_c$'s 121 couplings are authored from documented cyber
influence paths, not learned from incident data. Λ_c grades how well they explain
observed motion, and `coupling_adaptation_rate` can correct them, but the shipped matrix
is a design assertion.

**Simulated.** `XDPKernelDropEngine` and `ProcessQuarantineEngine` in
`adapters/hardware_accel.py` are in-process emulations. No eBPF or XDP program is loaded
into the kernel and no process is actually signalled. `KubernetesAdapter` and
`EBPFNetworkProbe.sample_network_probe` expose simulation entry points that are clearly
separated from the real `collect()` paths.

**Synthetic scenario harness.** `RedTeamBenchmarkEngine` measures the engine's
response to constructed attack vectors. No external SIEM/EDR product is evaluated.
Comparison, speedup, and suppression fields are `None` when unavailable. Earlier
synthetic comparison values have been removed from the code and example report.
Detection percentages describe these constructed scenarios only.

**Framework, not code.** The H¹¹ governance concepts ITH¹¹BAT, SGS and ACOS inform the
design philosophy but have no implementation in this repository.

---

## Project structure

```
h11_cga/
├── types.py                        # All type definitions
├── orchestrator.py                 # CyberGenesisEngine — the control loop
├── dcr_engine.py                   # ΔCR response prioritization
├── cli.py                          # h11-monitor live host daemon
├── cli_server.py                   # h11-server control plane launcher
├── core/
│   ├── mcc.py                      # Security state space
│   ├── dsa.py                      # Directional divergence
│   ├── dr.py                       # Divergence ratio
│   ├── hsa.py                      # Singularity approach
│   ├── ule.py                      # Universal limit engine
│   ├── cci.py                      # Cascade collapse index
│   ├── genesis.py                  # Π_c permission operator
│   ├── domain_nullification.py     # W_c(a) and K_c scope cost
│   ├── transformation_matrix.py    # T_c, 121 influence nodes
│   ├── cyber_genesis_equation.py   # G_c, the master equation
│   ├── advanced.py                 # R_genesis self-healing projector
│   ├── origin.py                   # Ψ_c origin attribution
│   ├── coherence.py                # Λ_c coherence and T_c self-correction
│   ├── origin_flux.py              # Φ₀ Origin Flux (Law 1)
│   ├── signature.py                # S_ig Sovereign Signature
│   └── law_conformance.py          # Λ₁₁ the 11 Laws, and Φ_H11
├── engines/                        # SENSE, DIVERGE, LIMIT, CONVERGE, ENCRYPT-IC
├── adapters/                       # VIE telemetry normalization + hub
├── ai_guardrails/                  # Agent and swarm tool-call guardrails
├── benchmarks/                     # Red-team scenario harness
├── license/                        # Open-core feature tiers
└── server/                         # Control plane REST API and dashboard
```

---

## Examples and tests

```bash
python examples/basic_usage.py                    # the control loop end to end
python examples/attack_scenarios.py               # the nine attack patterns
python examples/domain_nullification_demo.py      # scope reduction under pressure
python examples/reflexive_operators_demo.py       # Ψ_c, Λ_c, K_c, permission debt
python examples/first_knowledge_demo.py           # Φ₀, S_ig, the 11 Laws, Φ_H11
python examples/phase2_live_system_monitor.py     # live host telemetry
python examples/phase3_ai_agent_guardrail_demo.py # agent tool-call interception
python examples/phase4_control_plane_server_demo.py
```

```bash
pytest tests/ -v
```

---

## Author

**Mohamed Haseeb C M** ([@haseebcm](https://github.com/haseebcm))

Architecture, First Knowledge framework, and implementation.

---

## Citation

```bibtex
@software{h11_cga,
  author      = {Mohamed Haseeb C M},
  title       = {H\textsuperscript{11} Cyber Genesis Architecture},
  version     = {4.2.0},
  description = {A cybersecurity architecture governed by the 11 Universal Laws
                 of the H11 First Knowledge framework},
  url         = {https://github.com/haseebcm/Cyber-Genesis-Arc},
  license     = {MIT}
}
```

---

## License

[MIT License](LICENSE)
