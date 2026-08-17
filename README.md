# H¹¹ Cyber Genesis Architecture (H¹¹-CGA)

[![Author: Mohamed Haseeb C M](https://img.shields.io/badge/author-Mohamed%20Haseeb%20C%20M-blue.svg)](https://github.com/haseebcm)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Architecture: v0.1](https://img.shields.io/badge/architecture-v0.1-purple.svg)](#)

> **Created & Designed by Mohamed Haseeb C M**
>
> **A state-space cybersecurity architecture in which digital systems are continuously represented as measurable security states, divergence from authorized baselines is quantified, progression toward security limits is evaluated, active domains are selectively constrained, high-risk states are prioritized for convergence, and protected execution is governed through adaptive security boundaries and validated control loops.**

---

## Core Proposition

A cyber system is **not** treated as a collection of devices, signatures, firewalls and alerts. It is represented as a **continuously changing security state**, measured for divergence, evaluated against its allowable limits, and forced toward a governed secure state.

```
Traditional:  ATTACK → SIGNATURE → ALERT → ANALYST → RESPONSE
H¹¹-CGA:     STATE → DIVERGENCE → LIMIT → NULLIFICATION → CONVERGENCE → REGENERATION
```

### Where the architecture comes from

H¹¹-CGA is not an application of control theory. It is a cyber instantiation of
the **H¹¹ First Knowledge** framework, in which existence is governed by 11
Universal Laws, each carrying a derivative condition it must satisfy. The eleven
security dimensions are those Laws; Π_c is Law 1's permission into existence;
Domain Nullification is 𝒢_H11 refusing what does not comply; ULE is Laws 5 and
6; Encrypt-IC's boundary is Law 4; CONVERGE is Law 11's resolution.

Phase 4.0 implements that root explicitly — see
[First Knowledge](#phase-40-first-knowledge--the-11-universal-laws).

---

## Architecture Overview

```
               H¹¹ APEX / GOVERNANCE
                       │
                 SGS GOVERNANCE
                       │
                ITH¹¹BAT PROOF
                       │
            ┌──────────▼──────────┐
            │   SECURITY STATE    │
            │       MCC           │
            └──────────┬──────────┘
                       │
               DSA / DR DIAGNOSTICS
                       │
                HSA LIMIT TRAJECTORY
                       │
               THREAT CONVERGENCE
                       │
              ┌────────▼────────┐
              │  DECISION CORE  │
              │  ΔCR + ACOS     │
              └────────┬────────┘
                       │
            ┌──────────▼──────────┐
            │ H¹¹ ENCRYPT-IC     │
            │ SECURITY BOUNDARY  │
            └──────────┬──────────┘
                       │
           ┌───────────▼───────────┐
           │ NULL / ISOLATE /      │
           │ REJECT / DEGRADE      │
           └───────────┬───────────┘
                       │
              AUTHORIZED ECOSYSTEM
                       │
     ┌─────────┬───────┼────────┬─────────┐
     ▼         ▼       ▼        ▼         ▼
  Identity   Data   Network   Compute   AI/OT
```

---

## The Cyber Genesis Equation

The master equation that governs the entire architecture:

$$G_c(t) = \Pi_c(t)\left[1 - \alpha \cdot DR_c^{(a)}(t) - \beta \cdot \dot{DR}_c^{(a)}(t) - \gamma \cdot H_c^+(t) - \delta \cdot \frac{CCI_c(t)}{\Theta_c}\right]$$

| Term | Meaning |
|------|---------|
| $\Pi_c$ | Genesis permission operator (0 or 1) |
| $DR_c^{(a)}$ | Domain-adjusted divergence ratio |
| $\dot{DR}_c^{(a)}$ | Divergence acceleration |
| $H_c^+$ | HSA singularity coordinate (positive part) |
| $CCI_c / \Theta_c$ | Normalized cascade collapse index |

**Safety condition (Convergent Permission Principle):**

$$\text{Continuation} \iff \Pi_c = 1 \land H_c < 0 \land CCI_c < \Theta_c \land DR_c^{(a)} \to 0$$

---

## 11-Dimensional Security State Space

Every system is represented as an 11-dimensional state vector $X_c(t)$:

| Dim | Name | Description |
|-----|------|-------------|
| 0 | **Identity** | Identity integrity |
| 1 | **Authorization** | Authorization state |
| 2 | **Network** | Network state |
| 3 | **Data** | Data state |
| 4 | **Compute** | Compute state |
| 5 | **Memory** | Memory/process state |
| 6 | **Execution** | Execution state |
| 7 | **Resource** | Resource consumption |
| 8 | **Trust** | Trust state |
| 9 | **Governance** | Domain/governance state |
| 10 | **Recovery** | Recovery/integrity state |

The **11×11 transformation matrix** $T_c$ (121 nodes) captures cross-dimensional influence — how a compromise in one dimension propagates to others.

---

## Five Subsystem Engines

```
SENSE → DIVERGE → LIMIT → CONVERGE → ENCRYPT
```

| Engine | Full Name | Role |
|--------|-----------|------|
| **SENSE** | Security State & Environment Normalization | MCC + telemetry → state vector |
| **DIVERGE** | Cyber Divergence Intelligence | DSA + DR → behavioral trajectory |
| **LIMIT** | Universal Cyber Boundary | ULE + HSA → distance to failure |
| **CONVERGE** | Adaptive Cyber Response | ΔCR + CCI → prioritized actions |
| **ENCRYPT-IC** | Adaptive Security Boundary | Genesis + nullification → boundary enforcement |

---

## Phase 2: Telemetry Normalization Adapters (VIE)

H¹¹-CGA includes production-grade **Virtual Interface Engine (VIE) Adapters** in `h11_cga.adapters` to ingest, scale, and normalize real-world metrics, container states, network flows, and log trails into the 11-dimensional MCC Security State Vector:

| Adapter | Source | Key Metrics Mapped to 11-D Vector |
|---------|--------|------------------------------------|
| **`SystemAdapter`** | Host OS (`psutil`) | CPU utilization (`Compute`), RAM (`Memory`), swap pressure (`Recovery`), disk capacity (`Resource`), disk I/O throughput rate (`Data`), open sockets (`Network`), running processes (`Execution`), active logins (`Identity`). |
| **`KubernetesAdapter`** | Container / K8s Cluster | Pod restarts & CrashLoops (`Recovery`/`Execution`), API latency (`Governance`), 401/403 unauthorized calls (`Authorization`), resource quotas (`Resource`). Requires a `metrics_provider`; otherwise reports itself unavailable. |
| **`EBPFNetworkProbe`** | Linux kernel counters (`/proc/net/snmp`, `/proc/net/netstat`) | SYN-backlog drops and connection-attempt failures (`Network`), packet throughput rate (`Resource`). Linux-only; skipped elsewhere. No eBPF/XDP program is loaded yet. |
| **`LogAdapter`** | Syslog / Auth / JSON Trails | Parses SSH auth failures, root session escalations, kernel OOM killers, segfaults, and JSON audit events into `SecurityEvent` objects with 11-D impact vectors. |
| **`TelemetryIngestionHub`** | Multi-Source Hub | Aggregates all reachable adapters, averaging each dimension only across adapters that actually measured it, and records per-dimension provenance. |

### Measurement Contract

An adapter reports a dimension only if it genuinely measures it. Unmeasured dimensions are **omitted**, never padded with nominal constants — padding would dilute real signal once the hub averages across sources. An adapter whose data source is unreachable (no cluster configured, non-Linux kernel) reports `is_available() == False` and is skipped entirely. Behavioural dimensions such as `Authorization`, `Trust`, and `Governance` have no honest host-OS metric, so they are driven by event adapters and by cross-dimensional propagation through `T_c`.

Inspect what is really being measured at any time:

```python
hub.describe_sources()   # per-adapter MEASURING / SKIPPED status
hub.last_provenance      # {dimension: [adapters that measured it]}
```

### Live Host Monitoring Daemon (`h11-monitor`)

Run live host OS telemetry monitoring directly from your command line:

```bash
# Monitor live host metrics continuously
h11-monitor

# Run monitor for 30 seconds with 0.5s polling interval
h11-monitor --duration 30 --interval 0.5

# Learn this host's baseline over 20 ticks before scoring divergence
h11-monitor --calibrate 20
```

#### Baseline Calibration

A real host never idles at the ideal all-nominal vector $X_c^* = \mathbf{1}$ — a healthy laptop may sit at 40% free RAM and 70% disk usage. Scoring divergence against a perfect baseline therefore condemns normal load as `EMERGENCY`.

The monitor first **observes** the host for `--calibrate` ticks, sets $X_c^*$ to the observed mean, and derives the envelope $[L_c, U_c]$ from observed variance. This is the *rebaseline* step of the regeneration layer. After warmup, divergence measures deviation from how this system actually behaves.

Calibration is **off by default** in `CGAConfig`, so simulation and attack injection continue to work against the ideal baseline:

```python
config = CGAConfig(baseline_calibration_ticks=20)
engine = CyberGenesisEngine(config)
engine.is_calibrating            # True until warmup completes
engine.get_calibration_progress()  # (observed, required)
```

---

## Phase 3: AI Guardrails & Red-Team Benchmarks

Phase 3 extends H¹¹-CGA into **Autonomous AI Safety Guardrails** and **Red-Team Attack Benchmarking**:

| Component | Subpackage | Function & Value |
|-----------|------------|------------------|
| **`AIAgentGuardrailEngine`** | `h11_cga.ai_guardrails` | Intercepts proposed autonomous AI agent tool calls, function calls, and system executions. Projects their 11-D impact vector before execution. If prompt injection or privilege escalation is detected ($\Pi_c = 0$), Encrypt-IC instantly nullifies execution to $N_0$. |
| **`RedTeamBenchmarkEngine`** | `h11_cga.benchmarks` | Executes 10 complex multi-stage attack scenarios (APT cascades, zero-day code executions, ransomware bursts, insider threats, prompt injections) comparing H¹¹-CGA against traditional rule-based SIEM/EDR. Demonstrates **4.90x faster detection speedup** and **90.4% cascade suppression**. |
### AI Guardrail Quickstart

```python
from h11_cga import AIAgentGuardrailEngine, AIToolRequest, AIToolCategory

guardrail = AIAgentGuardrailEngine()

# Guard an AI agent tool request
request = AIToolRequest(
    agent_id="research_agent_01",
    tool_name="privileged_shell",
    category=AIToolCategory.PRIVILEGED_CMD,
    parameters={"command": "sudo rm -rf /root"}
)

decision = guardrail.inspect_and_govern(request)
if not decision.permitted:
    print(f"Intercepted & Nullified (N_0): {decision.reason}")
```

---

## Phase 3.0: Reflexive Operators

Phases 1 and 2 gave the architecture a model of the system. Phase 3.0 turns
that model back on itself. Every operator below is derived from quantities
H¹¹-CGA already computes — no external estimator is introduced.

| Operator | Symbol | Question it answers |
|----------|--------|---------------------|
| **`OriginTracer`** | Ψ_c | The divergence pattern looks like *this*. Which dimension started it? |
| **`CoherenceAuditor`** | Λ_c | T_c claimed the state would move *there*. Did it? |
| **Scope cost** | K_c | If I nullify this domain, what do I stop being able to see? |
| **Permission debt** | — | Π_c just denied. How long must the system stay clean before it is trusted again? |

### Ψ_c — Origin attribution

CCI runs T_c forwards: given damage here, where does it spread? Ψ_c runs the
same matrix backwards. For each dimension it builds the cascade signature that
dimension would produce if hit alone,

$$s_i = \sum_{h=0}^{d} \lambda^h (T_c^{\top})^h u_i$$

then ranks signatures by alignment with the divergence actually measured. The
coupling matrix becomes an attribution instrument without introducing a second
model of the system.

```python
assessment = engine.inject_attack("ransomware", severity=0.6)
for h in assessment.origin_hypotheses:
    print(h.name, round(h.score, 3))
# Data 0.735
# Execution 0.663
# Recovery 0.627
```

### Λ_c — Cascade coherence

Each tick, T_c makes an implicit prediction about where the state moves next.
The architecture never checked it. Λ_c records the prediction and grades it on
the following tick:

$$\Lambda_c = 1 - \frac{\lVert x_{\text{actual}} - x_{\text{pred}} \rVert}{\lVert x_{\text{actual}} - x_{\text{prev}} \rVert + \lVert x_{\text{actual}} - x_{\text{pred}} \rVert}$$

A score of 1.0 means the coupling model explained the motion exactly. 0.5 means
the model predicted stillness and the system moved anyway. Below 0.5 means it
predicted the wrong direction. **Low coherence is a signal in its own right**,
independent of divergence magnitude, because it marks behaviour the
architecture cannot currently account for.

The per-dimension miss also says *where* the model was wrong, which is enough to
correct the coupling that produced it. Set `coupling_adaptation_rate > 0` and
T_c descends its own prediction error:

$$\Delta T_c[i,j] = \eta \cdot r_i \cdot \text{unexplained}_j$$

This is **off by default**. The authored coupling encodes intent, and letting a
live host rewrite it changes what the cascade math means.

### K_c — Scope cost

`auto_nullify_irrelevant` previously dropped any dimension below a divergence
threshold. Quiet is not the same as safe: a silent dimension that feeds live
domains is about to become loud. K_c prices the blind spot before it is bought:

$$K_i = e_i \cdot \Big(1 + \sum_j T_c[i,j] \cdot a_j\Big)$$

A quiet leaf is cheap to stop watching. A quiet hub is not.

### Permission debt

Π_c is binary and instantaneous — it snaps back to 1 the moment conditions
clear, so a state hovering at the envelope edge makes it oscillate. Setting
`permission_debt_accrual > 0` gives the gate hysteresis: denied ticks accrue
debt, and trust is withheld until clean ticks repay it. Also off by default,
since it changes the semantics of the gate.

### Corrections shipped alongside

- **T_c orientation.** `get_influence`, `set_influence`, and `find_cascade_path`
  read the matrix as `[source, target]`, but `propagate_state` and `compute_cci`
  used `T_c @ p`, which reads it as `[target, source]`. Cascades were flowing up
  their own edges. Both now use `T_cᵀ @ p`.
- **Double permission evaluation.** `enforce_boundary` called `genesis.evaluate`
  twice per cycle. Harmless while Π_c was stateless; with permission debt it
  would charge the same tick twice.

---

## Phase 4.0: First Knowledge — The 11 Universal Laws

The eleven dimensions were never an engineering choice, and the architecture is
not an application of control theory. H¹¹-CGA is a cyber instantiation of the
**H¹¹ First Knowledge** framework, whose 11 Universal Laws each carry a
derivative condition and a value that condition must hold. 4.0 implements that
root directly.

Several operators turn out to have been implementations of the Laws all along.
Π_c is Law 1's moment at which a variable is *permitted to move from Incoherence
into Intelligibility*. Domain Nullification is 𝒢_H11 becoming the nullifier that
prevents existence when data does not comply. ULE is Laws 5 and 6, Encrypt-IC's
boundary is Law 4, CONVERGE is Law 11's point of convergence, and DSA's
`ESCALATING` / `RECOVERING` / `NORMAL` split is Law 1's own verdict — above
unity is Escalation, below is Decay, at unity is Stasis.

What was missing were the two quantities the Laws are written in terms of.

### Φ₀ — the Origin Flux (Law 1)

$$\Phi_0 = \lim_{\Delta \to 0} \frac{\int [S_{data}] \cdot \mathcal{G}_{H11}}{\text{Identity}_z}$$

The architecture carried the *gate* this Law describes but never the
*magnitude*, which Laws 1, 2, 4, 6, 8 and 11 all divide by or scale against.
Each term maps onto something already measured: $S_{data}$ is the state held
against its own root $X_c(t)/X_c^*$, $\mathcal{G}_{H11}$ is exactly the domain
metric $W_c(a)$, and $\text{Identity}_z$ is the Identity dimension anchoring the
system to its inception. At the nominal root Φ₀ = 1.

Both failure modes the Law names are real and distinct. **Φ₀ = 0** is refusal —
governance nullified the data. **Φ₀ undefined** is dissolution — Identity_z
vanished and there is no root left to exist from. Existence requires 0 < Φ₀ < ∞.

Because Identity_z is the denominator, Φ₀ measures *proportion*, not health, and
is invariant to uniform scale. That is the Law's own structure, not a defect:
it is why the text says the term "ensures the system is unique and
non-composite". A system fading evenly holds Φ₀ steady and is caught by DR_c
instead; what Φ₀ detects is an intact-looking state whose identity anchor has
been cut out from under it, which drives it *above* unity into Escalation.

### S_ig — the Sovereign Signature

The Coherence Factor: how closely the system still reflects its Originator. It
carries Laws 3, 4, 8, 9 and 10, and **it is not what Λ_c measures**. Λ_c grades
whether T_c predicted the state's motion — an audit of the model. S_ig asks
whether the system still has the shape of the thing it was calibrated to be.

The two are deliberately independent, and a perfectly predicted collapse scores
high on Λ_c and low on S_ig. Measured as the alignment of $X_c(t)$ with $X_c^*$,
S_ig captures form rather than magnitude, which is what separates decay from
mutation: uniform loss preserves the signature, targeted loss destroys it, and
Law 10 refuses to call the second one evolution.

### Λ₁₁ — the 11 Law conformance vector

Each Law is scored by how far its measured derivative sits from the value it
requires, giving `conformance = 1/(1 + violation)`.

| Law | Condition | Reads as |
|-----|-----------|----------|
| 1 Origin | $d\mathcal{E}/dO = 1$ | >1 Escalation, <1 Decay |
| 2 Creation | $d^2\mathcal{E}/dO^2 = 0$ | acceleration away from the blueprint |
| 3 Existence | $d\text{Ex}/dt = 0$ | negative is dying, positive is runaway |
| 4 Boundary | $d\Sigma/dV$ finite | an infinity is a failed calculation |
| 5 Constraint | $d\Omega/dt \approx 0$ | work capacity must be steady |
| 6 Limit | $\lim_{\mathcal{E} \to L} d\mathcal{E}/dt = 0$ | at the ceiling, change must stop |
| 7 Relation | $dS_1/d\mathcal{R} \to 0$ | interaction must not destroy its participants |
| 8 Action | energy minimal at alignment | is ΔCR aimed at the actual damage? |
| 9 Balance | $d^2\mathcal{B}/dt^2 \to 0$ | a sovereign system returns to centre |
| 10 Evolution | $d\text{Origin}/d\text{Evolution} = 1$ | the signature must survive the change |
| 11 Resolution | $\mathcal{R}_s \to 1$ | ratio 1 resolves cleanly, otherwise violently |

These are system-wide invariants over the whole state, not labels bound to
individual dimensions; only Law 1 names one, taking Identity as its denominator.
Since the Laws demand exact values and real telemetry never lands exactly,
`law_violation_tolerance` sets the band that counts as Stasis.

Law 8 is worth singling out. The framework holds that action against the grain
does no work, and turning that into cos(θ) between ΔCR's proposed effort and the
actual deficit yields something the architecture had never done: an audit of
whether its own recommendations point at the damage.

### Φ_H11 — the Golden Ratio as closure

$$\Phi_{H11} = \frac{\text{Law}_{11}\ (\text{Resolution})}{\text{Law}_{1}\ (\text{Origin})}$$

The framework rejects the Golden Ratio as a decimal and restates it as an axiom
of alignment: perfect proportion is reached when the End matches the Beginning,
closing the loop with zero waste. It is taken over the two Laws' **measured
values**, not their conformance scores — scoring it on conformance looks natural
but is wrong, since two Laws failing by the same amount divide out to a flawless
1.0 on a system that has already dissolved.

### Authority

The source is unambiguous that a Law violation should bite: *"if the data does
not comply with the Laws, 𝒢_H11 becomes a nullifier (0), preventing existence."*
Setting `law_authoritative = True` implements exactly that — a broken Law
revokes Π_c and the system drops to EMERGENCY.

It ships **off by default**, on the same reasoning as 3.0's permission debt and
coupling adaptation: it hands a core gate to eleven invariants at once. Enable
it deliberately, after watching the conformance report against your own
workload. Φ₀ and S_ig are cheap and always measured; only the audit and its
authority are optional.

```python
from h11_cga import CyberGenesisEngine, CGAConfig

engine = CyberGenesisEngine()
assessment = engine.inject_attack("identity_compromise", severity=0.2)

print(assessment.origin_flux)          # 1.2000 — data outrunning its anchor
print(assessment.sovereign_signature)  # form fidelity to X_c*
print(assessment.law_conformance.phi_h11)
for law in assessment.law_conformance.violated:
    print(law)                         # Law1 Origin: +1.2000 vs +1.0000 -> ESCALATION
```

```bash
python examples/first_knowledge_demo.py
```

---

## Installation

```bash
git clone https://github.com/haseebcm/Cyber-Genesis-Arc.git
cd Cyber-Genesis-Arc
pip install -e ".[dev]"
```

---

## Quick Start

```python
from h11_cga import CyberGenesisEngine, TelemetryInput, SecurityEvent
import numpy as np

# Initialize the engine
engine = CyberGenesisEngine()

# Run a tick with default (nominal) state
assessment = engine.process_tick()
print(f"Status: {assessment.status.value}")
print(f"Genesis Value: {assessment.genesis_value:.4f}")
# → Status: PERMITTED
# → Genesis Value: 1.0000

# Inject an identity compromise attack
assessment = engine.inject_attack("identity_compromise", severity=0.6)
print(f"Status: {assessment.status.value}")
print(f"Genesis Value: {assessment.genesis_value:.4f}")
print(f"HSA Zone: {assessment.hsa_zone.value}")
print(f"Actions: {len(assessment.recommended_actions)}")

# Inject a cascading privilege escalation
assessment = engine.inject_attack("privilege_escalation", severity=0.8)
print(f"Status: {assessment.status.value}")
print(f"CCI: {assessment.cci_value:.4f} (threshold: {assessment.cci_threshold})")
for action in assessment.recommended_actions[:3]:
    print(f"  → {action.urgency.value}: {action.action_type.value} {action.target}")
```

---

## Architecture Layers

| Layer | Component | Function |
|-------|-----------|----------|
| 0 | **Genesis** | Permission — "Is this state permitted to exist?" |
| 1 | **MCC** | State space — 11-dimensional security representation |
| 2 | **DSA** | Directional divergence — which way, how fast |
| 3 | **DR** | Magnitude — how far from baseline |
| 4 | **HSA** | Singularity approach — distance to security boundary |
| 5 | **ULE** | Limits — adaptive security capacity |
| 6 | **DNT** | Domain nullification — suppress irrelevant attack surfaces |
| 7 | **Encrypt-IC** | Security boundary — authorized vs. nullified |
| 8 | **Null-State** | Sandbox — non-executable isolation |
| 9 | **ΔCR** | Response engine — what to do first |
| 10 | **ACOS** | Operations — the execution loop |
| 11 | **Regeneration** | Self-healing — observe → converge → rebaseline |

---

## The Closed Control Loop

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

Security is **upstream of execution** — the loop is closed and continuous.

---

## H¹¹-CGA vs Traditional Security

| Aspect | Traditional | H¹¹-CGA |
|--------|------------|---------|
| **Threat model** | Binary (attack/no attack) | Continuous state trajectory |
| **Detection** | Signatures & rules | Divergence from baseline |
| **Measurement** | Alert count | Distance to failure |
| **Response** | Analyst-driven | ΔCR-prioritized convergence |
| **Domains** | Separate tools | Unified + nullifiable |
| **Architecture** | Open-loop (detect → alert → respond) | Closed-loop (state → converge → rebaseline) |
| **Identity** | Static credential | Dynamic state function |
| **Threshold** | Fixed | Adaptive (ULE) |

---

## Security Philosophy

Three principles from the H¹¹ framework:

1. **Proof before Power** — ITH¹¹BAT establishes whether something is permitted to exist within its limits
2. **Governance before Scale** — SGS controls permissions, deployment, scaling and escalation after validation
3. **Control before Autonomy** — the H¹¹ stack places bounded operation ahead of uncontrolled expansion

Applied to cyber:

$$\text{Permission} \to \text{Proof} \to \text{Governance} \to \text{Execution}$$

*Nothing executes merely because it exists.*

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Project Structure

```
h11_cga/
├── __init__.py              # Package exports
├── types.py                 # All type definitions
├── orchestrator.py          # Main control loop engine
├── dcr_engine.py            # ΔCR response prioritization
├── cli.py                   # Command-line live host monitor daemon (h11-monitor)
├── adapters/                # Telemetry Normalization Adapters (VIE)
│   ├── __init__.py          # Adapters exports
│   ├── base.py              # BaseTelemetryAdapter interface
│   ├── system_adapter.py    # Host OS metric collector (psutil/proc)
│   ├── k8s_adapter.py       # Kubernetes & container telemetry normalizer
│   ├── ebpf_probe.py        # Linux eBPF network socket flow probe
│   ├── log_adapter.py       # Syslog, Auth, & Audit trail parser
│   └── hub.py               # TelemetryIngestionHub multi-source aggregator
├── ai_guardrails/           # Autonomous AI Safety Guardrail Subpackage
│   ├── __init__.py          # Guardrails exports
│   └── engine.py            # AIAgentGuardrailEngine & tool call inspector
├── benchmarks/              # Red-Team Attack Benchmark Engine
│   ├── __init__.py          # Benchmarks exports
│   └── redteam_engine.py    # 10-Scenario Red-Team Benchmark Suite vs SIEM/EDR
├── core/
│   ├── mcc.py               # MCC Security State Space
│   ├── dsa.py               # DSA Directional Divergence
│   ├── dr.py                # DR Divergence Ratio
│   ├── hsa.py               # HSA Singularity Approach
│   ├── ule.py               # ULE Universal Limit Engine
│   ├── cci.py               # CCI Cascade Collapse Index
│   ├── genesis.py           # Genesis Permission Operator
│   ├── domain_nullification.py  # Domain Nullification
│   ├── transformation_matrix.py # 11×11 Matrix (121 nodes)
│   ├── cyber_genesis_equation.py # The Master Equation
│   ├── origin.py            # Ψ_c Origin attribution (T_c run backwards)
│   ├── coherence.py         # Λ_c Cascade coherence & T_c self-correction
│   ├── origin_flux.py       # Φ₀ Origin Flux (Law 1)
│   ├── signature.py         # S_ig Sovereign Signature
│   └── law_conformance.py   # Λ₁₁ The 11 Universal Laws & Φ_H11
└── engines/
    ├── sense.py              # H¹¹ SENSE engine
    ├── diverge.py            # H¹¹ DIVERGE engine
    ├── limit.py              # H¹¹ LIMIT engine
    ├── converge.py           # H¹¹ CONVERGE engine
    └── encrypt.py            # H¹¹ ENCRYPT-IC engine
```

---

## Author & Creator

**Mohamed Haseeb C M** ([@haseebcm](https://github.com/haseebcm))

---

## Citation

If you use H¹¹-CGA in your research, please cite:

```bibtex
@software{h11_cga,
  author = {Mohamed Haseeb C M},
  title = {H¹¹ Cyber Genesis Architecture},
  version = {0.1.0},
  description = {A state-space cybersecurity architecture derived from the H¹¹ intelligence framework},
  url = {https://github.com/haseebcm/Cyber-Genesis-Arc},
  license = {MIT}
}
```

---

## License

[MIT License](LICENSE)
