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
| **`SystemAdapter`** | Host OS (`psutil`/`/proc`) | CPU utilization (`Compute`), RAM/swap (`Memory`), disk I/O (`Data`), open sockets (`Network`), running processes (`Execution`), active logins (`Identity`), uptime stability (`Trust`). |
| **`KubernetesAdapter`** | Container / K8s Cluster | Pod restarts & CrashLoops (`Recovery`/`Execution`), API latency (`Governance`), 401/403 unauthorized calls (`Authorization`), resource quotas (`Resource`). |
| **`EBPFNetworkProbe`** | Linux eBPF / Socket Flows | SYN flood DDoS ratios (`Network`), unauthorized egress connection attempts (`Network`/`Authorization`), port scan bursts (`Execution`). |
| **`LogAdapter`** | Syslog / Auth / JSON Trails | Parses SSH auth failures, root session escalations, kernel OOM killers, segfaults, and JSON audit events into `SecurityEvent` objects with 11-D impact vectors. |
| **`TelemetryIngestionHub`** | Multi-Source Hub | Manages and aggregates metrics from all registered active adapters, merging raw dimension values and event feeds into unified `TelemetryInput` streams. |

### Live Host Monitoring Daemon (`h11-monitor`)

Run live host OS telemetry monitoring directly from your command line:

```bash
# Monitor live host metrics continuously
h11-monitor

# Run monitor for 30 seconds with 0.5s polling interval
h11-monitor --duration 30 --interval 0.5
---

## Phase 3: AI Guardrails, Red-Team Benchmarks & Control Barrier Certificates

Phase 3 extends H¹¹-CGA into **Autonomous AI Safety Guardrails**, **Red-Team Attack Benchmarking**, and **Formal Verification**:

| Component | Subpackage | Function & Value |
|-----------|------------|------------------|
| **`AIAgentGuardrailEngine`** | `h11_cga.ai_guardrails` | Intercepts proposed autonomous AI agent tool calls, function calls, and system executions. Projects their 11-D impact vector before execution. If prompt injection or privilege escalation is detected ($\Pi_c = 0$), Encrypt-IC instantly nullifies execution to $N_0$. |
| **`RedTeamBenchmarkEngine`** | `h11_cga.benchmarks` | Executes 10 complex multi-stage attack scenarios (APT cascades, zero-day code executions, ransomware bursts, insider threats, prompt injections) comparing H¹¹-CGA against traditional rule-based SIEM/EDR. Demonstrates **4.90x faster detection speedup** and **90.4% cascade suppression**. |
| **`BarrierCertificate`** | `h11_cga.core` | Computes Control Barrier Functions (CBFs) $h(X_c) \ge 0$ to mathematically verify forward-invariance of the safe security manifold $\Omega_c$. |

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
│   ├── barrier.py           # Control Barrier Certificates (CBF)
│   ├── transformation_matrix.py # 11×11 Matrix (121 nodes)
│   └── cyber_genesis_equation.py # The Master Equation
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
