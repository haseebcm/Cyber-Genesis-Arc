"""
H¹¹-CGA Core Type Definitions
==============================

All data structures used across the H¹¹ Cyber Genesis Architecture.
Built on dataclasses with NumPy arrays for the mathematical engine.

The 11 security dimensions (matching the H¹¹ organizational constant):
    0: Identity       - identity integrity
    1: Authorization   - authorization state
    2: Network         - network state
    3: Data            - data state
    4: Compute         - compute state
    5: Memory          - memory/process state
    6: Execution       - execution state
    7: Resource        - resource consumption state
    8: Trust           - trust state
    9: Governance      - domain/governance state
   10: Recovery        - recovery/integrity state
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any

import numpy as np

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NUM_DIMENSIONS = 11
"""The H¹¹ organizational constant — 11 security dimensions."""

DIMENSION_NAMES: tuple[str, ...] = (
    "Identity",
    "Authorization",
    "Network",
    "Data",
    "Compute",
    "Memory",
    "Execution",
    "Resource",
    "Trust",
    "Governance",
    "Recovery",
)

DIMENSION_INDEX: dict[str, int] = {
    name.lower(): i for i, name in enumerate(DIMENSION_NAMES)
}

NUM_TRANSFORMATION_NODES = NUM_DIMENSIONS * NUM_DIMENSIONS  # 121

LAW_NAMES: tuple[str, ...] = (
    "Origin",
    "Creation",
    "Existence",
    "Boundary",
    "Constraint",
    "Limit",
    "Relation",
    "Action",
    "Balance",
    "Evolution",
    "Resolution",
)
"""The 11 Universal Laws of the H¹¹ framework, in derivation order.

These are system-wide invariants evaluated over the whole state, not labels
attached to individual dimensions. Only Law 1 names a specific dimension:
Identity supplies the root signature Identity_z in its denominator.

Grouped by the framework as Seed (1-3), Vessel (4-6), Interaction (7-9),
and Return (10-11).
"""

LAW_GROUPS: dict[str, tuple[int, ...]] = {
    "Seed": (1, 2, 3),
    "Vessel": (4, 5, 6),
    "Interaction": (7, 8, 9),
    "Return": (10, 11),
}
"""The four arcs the 11 Laws fall into."""


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SystemStatus(enum.Enum):
    """Overall system status derived from the Cyber Genesis Equation."""

    PERMITTED = "PERMITTED"
    """G_c ≈ 1 — all conditions satisfied, system operating normally."""

    MONITORING = "MONITORING"
    """0.7 ≤ G_c < 1 — minor divergence detected, under observation."""

    WARNING = "WARNING"
    """0.4 ≤ G_c < 0.7 — significant divergence, prepare containment."""

    CRITICAL = "CRITICAL"
    """0.1 ≤ G_c < 0.4 — approaching security boundary."""

    CONTAINMENT = "CONTAINMENT"
    """0 < G_c < 0.1 — active containment required."""

    EMERGENCY = "EMERGENCY"
    """G_c ≤ 0 or Π_c = 0 — permission revoked, emergency isolation."""


class DivergenceClassification(enum.Enum):
    """Classification of the divergence state from DSA analysis."""

    NORMAL = "NORMAL"
    """d_s ≈ 0 — within baseline tolerance."""

    RECOVERING = "RECOVERING"
    """‖d_s‖ > 0, d/dt ‖d_s‖ < 0 — abnormal but improving."""

    ESCALATING = "ESCALATING"
    """‖d_s‖ > 0, d/dt ‖d_s‖ > 0 — abnormal and worsening."""


class HSAZone(enum.Enum):
    """HSA singularity zone classification."""

    CONTROLLED = "CONTROLLED"
    """H_c < 0 — security buffer exceeds threat pressure."""

    CRITICAL = "CRITICAL"
    """H_c ≈ 0 — at the security boundary."""

    SINGULARITY = "SINGULARITY"
    """H_c > 0 — past the boundary, containment required."""


class ActionType(enum.Enum):
    """Types of security response actions from ΔCR."""

    MONITOR = "MONITOR"
    PREPARE = "PREPARE"
    ISOLATE = "ISOLATE"
    REVOKE = "REVOKE"
    ROTATE = "ROTATE"
    QUARANTINE = "QUARANTINE"
    RESTORE = "RESTORE"
    REVALIDATE = "REVALIDATE"
    NULLIFY = "NULLIFY"
    EMERGENCY_SHUTDOWN = "EMERGENCY_SHUTDOWN"


class ActionUrgency(enum.Enum):
    """Urgency level for response actions."""

    LOW = "LOW"
    """ΔCR < 0 — monitor only."""

    MEDIUM = "MEDIUM"
    """ΔCR ≈ 0 — prepare containment."""

    HIGH = "HIGH"
    """ΔCR > 0 — immediate containment."""

    CRITICAL = "CRITICAL"
    """ΔCR >> 0 — emergency isolation."""


class EncryptICClassification(enum.Enum):
    """Encrypt-IC input classification."""

    AUTHORIZED = "AUTHORIZED"
    UNCERTAIN = "UNCERTAIN"
    DIVERGENT = "DIVERGENT"
    UNAUTHORIZED = "UNAUTHORIZED"


class LawVerdict(enum.Enum):
    """How a measured derivative sits against the value its Law requires."""

    STASIS = "STASIS"
    """Measured ≈ required — the Law is satisfied."""

    ESCALATION = "ESCALATION"
    """Measured above required — growth the Law does not sanction."""

    DECAY = "DECAY"
    """Measured below required — the system is losing what it had."""

    UNDEFINED = "UNDEFINED"
    """The quantity could not be formed at all; Φ₀ has no denominator."""


# ---------------------------------------------------------------------------
# Core State Structures
# ---------------------------------------------------------------------------

@dataclass
class SecurityState:
    """
    The 11-dimensional MCC security state vector X_c(t).

    Each dimension is a normalized value in [0, 1] where:
        1.0 = fully nominal / secure
        0.0 = fully compromised / failed
    """

    vector: np.ndarray = field(default_factory=lambda: np.ones(NUM_DIMENSIONS))
    """The raw 11-dimensional state vector."""

    timestamp: float = field(default_factory=time.time)
    """Timestamp when this state was recorded."""

    def __post_init__(self) -> None:
        self.vector = np.array(self.vector, dtype=np.float64, copy=True)
        if self.vector.shape != (NUM_DIMENSIONS,):
            raise ValueError(
                f"State vector must have {NUM_DIMENSIONS} dimensions, "
                f"got {self.vector.shape}"
            )

        if not np.all(np.isfinite(self.vector)) or np.any((self.vector < 0) | (self.vector > 1)):
            raise ValueError("State coordinates must be finite and in [0, 1]")

    def __getitem__(self, key: int | str) -> float:
        if isinstance(key, str):
            key = DIMENSION_INDEX[key.lower()]
        return float(self.vector[key])

    def __setitem__(self, key: int | str, value: float) -> None:
        if isinstance(key, str):
            key = DIMENSION_INDEX[key.lower()]
        self.vector[key] = value

    def copy(self) -> SecurityState:
        return SecurityState(vector=self.vector.copy(), timestamp=self.timestamp)

    @property
    def dimension_dict(self) -> dict[str, float]:
        """Return state as {dimension_name: value} dict."""
        return {
            name: float(self.vector[i])
            for i, name in enumerate(DIMENSION_NAMES)
        }


@dataclass
class SecurityBaseline:
    """
    Reference state X_c* with the allowable security envelope.

    The envelope defines the corridor [L_c, U_c] within which
    the system is considered to be operating normally.
    """

    reference: np.ndarray = field(
        default_factory=lambda: np.ones(NUM_DIMENSIONS)
    )
    """The baseline/reference state X_c*."""

    lower_bound: np.ndarray = field(
        default_factory=lambda: np.full(NUM_DIMENSIONS, 0.7)
    )
    """Lower bound of the allowable envelope L_c."""

    upper_bound: np.ndarray = field(
        default_factory=lambda: np.full(NUM_DIMENSIONS, 1.0)
    )
    """Upper bound of the allowable envelope U_c."""

    def __post_init__(self) -> None:
        self.reference = np.asarray(self.reference, dtype=np.float64)
        self.lower_bound = np.asarray(self.lower_bound, dtype=np.float64)
        self.upper_bound = np.asarray(self.upper_bound, dtype=np.float64)
        for value in (self.reference, self.lower_bound, self.upper_bound):
            if value.shape != (NUM_DIMENSIONS,) or not np.all(np.isfinite(value)):
                raise ValueError("Baseline arrays must be finite 11-dimensional vectors")
        if np.any(self.lower_bound > self.reference) or np.any(self.reference > self.upper_bound):
            raise ValueError("Baseline reference must lie inside its envelope")


    def is_within_envelope(self, state: SecurityState) -> bool:
        """Check if a state is within the allowable envelope."""
        return bool(
            np.all(state.vector >= self.lower_bound)
            and np.all(state.vector <= self.upper_bound)
        )

    def envelope_utilization(self, state: SecurityState) -> np.ndarray:
        """
        Compute per-dimension utilization of the envelope.
        0.0 = at reference, 1.0 = at boundary.
        """
        half_width = (self.upper_bound - self.lower_bound) / 2.0
        center = (self.upper_bound + self.lower_bound) / 2.0
        safe_width = np.where(half_width > 0, half_width, 1.0)
        return np.abs(state.vector - center) / safe_width


@dataclass
class SecurityOrigin:
    """
    H¹¹ Security Origin O_s = {I, R, P, L, B, D}.

    Every protected system receives a defined origin that establishes
    what the system is, what it needs, and what it is allowed to do.
    """

    identity: str = ""
    """I — unique identity of the protected system."""

    required_resources: list[str] = field(default_factory=list)
    """R — resources the system requires to operate."""

    permissions: dict[str, bool] = field(default_factory=dict)
    """P — explicit permissions granted to this system."""

    security_limits: dict[str, float] = field(default_factory=dict)
    """L — security limits / thresholds for this system."""

    baseline_profile: str = ""
    """B — identifier for the baseline state profile."""

    authorized_domains: list[str] = field(default_factory=list)
    """D — domains this system is authorized to interact with."""


# ---------------------------------------------------------------------------
# Divergence & Threat Assessment
# ---------------------------------------------------------------------------

@dataclass
class DivergenceResult:
    """
    Result of DSA directional divergence analysis.

    D_c(t) = X_c(t) - X_c*
    """

    divergence_vector: np.ndarray = field(
        default_factory=lambda: np.zeros(NUM_DIMENSIONS)
    )
    """Per-dimension divergence D_c(t)."""

    acceleration_vector: np.ndarray = field(
        default_factory=lambda: np.zeros(NUM_DIMENSIONS)
    )
    """Per-dimension divergence acceleration d/dt D_c(t)."""

    magnitude: float = 0.0
    """Overall divergence magnitude ‖D_c‖."""

    acceleration_magnitude: float = 0.0
    """Overall acceleration magnitude ‖d/dt D_c‖."""

    classification: DivergenceClassification = DivergenceClassification.NORMAL
    """Classified state: NORMAL, RECOVERING, or ESCALATING."""

    timestamp: float = field(default_factory=time.time)


@dataclass
class DomainVector:
    """
    Active-domain vector a(t) for domain nullification.

    Each element a_i ∈ [0, 1] defines the permitted contribution
    of each security domain. Setting a_i = 0 nullifies that domain.
    """

    activations: np.ndarray = field(
        default_factory=lambda: np.ones(NUM_DIMENSIONS)
    )
    """Per-domain activation levels."""

    def __post_init__(self) -> None:
        self.activations = np.asarray(self.activations, dtype=np.float64)
        self.activations = np.clip(self.activations, 0.0, 1.0)

    def nullify(self, dimension: int | str) -> None:
        """Nullify a domain — set activation to 0."""
        if isinstance(dimension, str):
            dimension = DIMENSION_INDEX[dimension.lower()]
        self.activations[dimension] = 0.0

    def activate(self, dimension: int | str, level: float = 1.0) -> None:
        """Set activation level for a domain."""
        if isinstance(dimension, str):
            dimension = DIMENSION_INDEX[dimension.lower()]
        self.activations[dimension] = np.clip(level, 0.0, 1.0)

    @property
    def active_domains(self) -> list[str]:
        """Return names of domains with non-zero activation."""
        return [
            DIMENSION_NAMES[i]
            for i in range(NUM_DIMENSIONS)
            if self.activations[i] > 0
        ]

    @property
    def nullified_domains(self) -> list[str]:
        """Return names of nullified domains."""
        return [
            DIMENSION_NAMES[i]
            for i in range(NUM_DIMENSIONS)
            if self.activations[i] == 0
        ]

    @property
    def complexity_ratio(self) -> float:
        """Ratio of active dimensions to total — lower = less attack surface."""
        return float(np.sum(self.activations > 0)) / NUM_DIMENSIONS


@dataclass
class OriginHypothesis:
    """A candidate origin for an observed divergence pattern (Ψ_c)."""

    dimension: int = -1
    """Index of the dimension proposed as the origin."""

    name: str = ""
    """Human-readable dimension name."""

    score: float = 0.0
    """Alignment between this origin's cascade signature and what was measured."""

    explained_fraction: float = 0.0
    """Share of the observed divergence magnitude this origin accounts for."""

    observed_error: float = 0.0
    """Divergence measured on the origin dimension itself."""

    def __repr__(self) -> str:
        return (
            f"OriginHypothesis({self.name}, score={self.score:.4f}, "
            f"explains={self.explained_fraction:.2%})"
        )


@dataclass
class CascadePath:
    """A single cascade propagation path through the transformation matrix."""

    path: list[int] = field(default_factory=list)
    """Ordered list of dimension indices in the cascade."""

    total_influence: float = 0.0
    """Cumulative influence along the path."""

    @property
    def path_names(self) -> list[str]:
        return [DIMENSION_NAMES[i] for i in self.path]

    def __repr__(self) -> str:
        return f"CascadePath({' → '.join(self.path_names)}, influence={self.total_influence:.4f})"


# ---------------------------------------------------------------------------
# First Knowledge — Law conformance
# ---------------------------------------------------------------------------

@dataclass
class LawConformance:
    """How the system measured against one Universal Law this tick."""

    law: int = 0
    """Law number, 1-11."""

    name: str = ""
    """Law name."""

    measured: float = 0.0
    """The derivative the system actually produced."""

    required: float = 0.0
    """The value this Law requires that derivative to hold."""

    violation: float = 0.0
    """|measured − required| — distance from the Law."""

    conformance: float = 1.0
    """1/(1 + violation) — bounded (0, 1], where 1 is exact conformance."""

    verdict: LawVerdict = LawVerdict.STASIS
    """Direction of the deviation, in the framework's own terms."""

    def __repr__(self) -> str:
        return (
            f"Law{self.law} {self.name}: {self.measured:+.4f} vs {self.required:+.4f} "
            f"-> {self.verdict.value} ({self.conformance:.3f})"
        )


@dataclass
class LawConformanceReport:
    """The full 11-Law audit for one tick, plus the closure of the arc."""

    laws: list[LawConformance] = field(default_factory=list)
    """Conformance for each of the 11 Laws, in order."""

    phi_h11: float = 1.0
    """Φ_H11 = Law₁₁ / Law₁ — the arc closes when the End matches the Beginning."""

    origin_flux: float = 1.0
    """Φ₀ — the magnitude of existence this tick."""

    origin_defined: bool = True
    """False when Identity_z vanished and Φ₀ could not be formed at all."""

    sovereign_signature: float = 1.0
    """S_ig — how closely the system still reflects its Originator."""

    mean_conformance: float = 1.0
    """Average conformance across all 11 Laws."""

    def __post_init__(self) -> None:
        if self.laws and self.mean_conformance == 1.0:
            self.mean_conformance = float(
                np.mean([law.conformance for law in self.laws])
            )

    @property
    def violated(self) -> list[LawConformance]:
        """Laws whose verdict is anything other than Stasis."""
        return [law for law in self.laws if law.verdict is not LawVerdict.STASIS]

    @property
    def sovereign(self) -> bool:
        """True when every Law is satisfied and the origin is well-formed."""
        return self.origin_defined and not self.violated

    @property
    def worst_law(self) -> LawConformance | None:
        """The Law the system is furthest from, if any is broken."""
        broken = self.violated
        return min(broken, key=lambda law: law.conformance) if broken else None

    def summary(self) -> dict[str, Any]:
        """Concise dict for logging and dashboards."""
        worst = self.worst_law
        return {
            "phi_0": round(self.origin_flux, 4),
            "origin_defined": self.origin_defined,
            "s_ig": round(self.sovereign_signature, 4),
            "phi_h11": round(self.phi_h11, 4),
            "mean_conformance": round(self.mean_conformance, 4),
            "sovereign": self.sovereign,
            "violated_laws": [law.law for law in self.violated],
            "worst_law": worst.name if worst else None,
        }


# ---------------------------------------------------------------------------
# Response & Action
# ---------------------------------------------------------------------------

@dataclass
class ResponseAction:
    """A single ΔCR-prioritized response action."""

    action_type: ActionType = ActionType.MONITOR
    """Type of action to take."""

    target: str = ""
    """Target of the action (e.g., node ID, session ID, domain)."""

    urgency: ActionUrgency = ActionUrgency.LOW
    """Urgency level."""

    dcr_score: float = 0.0
    """Raw ΔCR score that determined this action's priority."""

    description: str = ""
    """Human-readable description of the action."""

    dimension: int = -1
    """Primary security dimension this action addresses (-1 = global)."""

    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Comprehensive Assessment
# ---------------------------------------------------------------------------

@dataclass
class ThreatAssessment:
    """
    Complete threat assessment from one cycle of the control loop.

    Combines outputs from all layers: MCC → DSA → DR → HSA → ULE → CCI →
    Genesis → Domain Nullification → ΔCR → Cyber Genesis Equation.
    """

    # --- State ---
    current_state: SecurityState = field(default_factory=SecurityState)
    baseline: SecurityBaseline = field(default_factory=SecurityBaseline)

    # --- Divergence (DSA/DR) ---
    divergence: DivergenceResult = field(default_factory=DivergenceResult)
    dr_value: float = 0.0
    """DR_c(t) — raw divergence ratio magnitude."""
    dr_adjusted: float = 0.0
    """DR_c^(a)(t) — domain-adjusted divergence ratio."""
    dr_rate: float = 0.0
    """d/dt DR_c — divergence acceleration."""

    # --- Singularity (HSA) ---
    hsa_coordinate: float = 0.0
    """H_c(t) = k·DR_c - B_c — cyber singularity coordinate."""
    hsa_zone: HSAZone = HSAZone.CONTROLLED
    security_buffer: float = 1.0
    """B_c(t) — remaining security buffer."""

    # --- Limits (ULE) ---
    limit_utilization: float = 0.0
    """Ω_s = Demand / Capacity."""
    within_limits: bool = True

    # --- Cascade (CCI) ---
    cci_value: float = 0.0
    """CCI_c(t) — cascade collapse index."""
    cci_threshold: float = 1.0
    """Θ_c — cascade threshold."""
    cci_subcritical: bool = True
    critical_cascade_paths: list[CascadePath] = field(default_factory=list)

    # --- Permission (Genesis) ---
    permission: float = 1.0
    """Π_c — genesis permission operator (0 or 1)."""

    # --- Domain ---
    domain_vector: DomainVector = field(default_factory=DomainVector)
    domain_metric: float = 1.0
    """W_c(a) — domain-nullified metric."""

    # --- Genesis Equation ---
    genesis_value: float = 1.0
    """G_c(t) — the master Cyber Genesis Equation output."""
    genesis_terms: dict[str, float] = field(default_factory=dict)
    """Breakdown of each term in the Genesis Equation."""

    # --- Encrypt-IC ---
    encrypt_classification: EncryptICClassification = EncryptICClassification.AUTHORIZED
    """Encrypt-IC boundary classification for this cycle."""

    # --- Origin attribution (Ψ_c) ---
    origin_hypotheses: list[OriginHypothesis] = field(default_factory=list)
    """Candidate origins for this cycle's divergence, best first."""

    # --- Cascade coherence (Λ_c) ---
    coherence: float = 1.0
    """Λ_c — how well T_c predicted the state's actual motion this tick."""
    unexplained_vector: np.ndarray = field(
        default_factory=lambda: np.zeros(NUM_DIMENSIONS)
    )
    """Per-dimension motion T_c did not account for."""

    # --- Scope cost (K_c) ---
    nullification_cost: np.ndarray = field(
        default_factory=lambda: np.zeros(NUM_DIMENSIONS)
    )
    """K_c — visibility forfeited by nullifying each dimension."""

    # --- Permission debt ---
    permission_debt: float = 0.0
    """Outstanding caution owed before Π_c may return to 1."""

    # --- First Knowledge (Φ₀, S_ig, the 11 Laws) ---
    origin_flux: float = 1.0
    """Φ₀ — magnitude of existence; 1.0 at the nominal root."""

    origin_defined: bool = True
    """False when Identity_z vanished, i.e. the system has no root to exist from."""

    sovereign_signature: float = 1.0
    """S_ig — fidelity of the current form to its Originator."""

    law_conformance: LawConformanceReport | None = None
    """The 11-Law audit for this tick, when the Law layer is enabled."""

    # --- Regeneration (closed loop) ---
    time_to_boundary: float | None = None
    """HSA linear estimate of ticks-to-singularity; None if receding."""
    safety_conditions: dict[str, bool] = field(default_factory=dict)
    """Convergent Permission Principle checks."""
    regeneration_energy: float = 0.0
    """Energy applied by R_genesis during closed-loop regeneration."""

    # --- Response ---
    status: SystemStatus = SystemStatus.PERMITTED
    """Overall system status."""
    recommended_actions: list[ResponseAction] = field(default_factory=list)
    """ΔCR-prioritized response actions."""

    timestamp: float = field(default_factory=time.time)

    def summary(self) -> dict[str, Any]:
        """Return a concise summary dict for logging/display."""
        return {
            "status": self.status.value,
            "genesis_value": round(self.genesis_value, 4),
            "permission": self.permission,
            "dr_value": round(self.dr_value, 4),
            "dr_adjusted": round(self.dr_adjusted, 4),
            "dr_rate": round(self.dr_rate, 4),
            "hsa_coordinate": round(self.hsa_coordinate, 4),
            "hsa_zone": self.hsa_zone.value,
            "security_buffer": round(self.security_buffer, 4),
            "limit_utilization": round(self.limit_utilization, 4),
            "cci_value": round(self.cci_value, 4),
            "cci_subcritical": self.cci_subcritical,
            "domain_metric": round(self.domain_metric, 4),
            "encrypt_classification": self.encrypt_classification.value,
            "coherence": round(self.coherence, 4),
            "permission_debt": round(self.permission_debt, 4),
            "likely_origin": self.origin_hypotheses[0].name if self.origin_hypotheses else None,
            "origin_flux": round(self.origin_flux, 4),
            "sovereign_signature": round(self.sovereign_signature, 4),
            "phi_h11": (
                round(self.law_conformance.phi_h11, 4) if self.law_conformance else None
            ),
            "laws_violated": (
                [law.law for law in self.law_conformance.violated]
                if self.law_conformance
                else []
            ),
            "num_actions": len(self.recommended_actions),
        }


# ---------------------------------------------------------------------------
# Event / Telemetry Input
# ---------------------------------------------------------------------------

@dataclass
class SecurityEvent:
    """
    A security event or telemetry input to be processed by the control loop.
    """

    event_type: str = ""
    """Type of event (e.g., 'auth_failure', 'network_anomaly', 'privilege_escalation')."""

    source: str = ""
    """Source system or sensor."""

    target_dimensions: list[int] = field(default_factory=list)
    """Which security dimensions this event affects."""

    impact: np.ndarray = field(
        default_factory=lambda: np.zeros(NUM_DIMENSIONS)
    )
    """Per-dimension impact (negative = degradation, positive = improvement)."""

    severity: float = 0.0
    """Severity score [0, 1]."""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Additional event metadata."""

    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        self.impact = np.array(self.impact, dtype=np.float64, copy=True)
        if self.impact.shape != (NUM_DIMENSIONS,) or not np.all(np.isfinite(self.impact)):
            raise ValueError("Event impact must be a finite 11-dimensional vector")
        if not np.isfinite(self.severity) or not 0 <= self.severity <= 1:
            raise ValueError("Event severity must be in [0, 1]")


@dataclass
class TelemetryInput:
    """Raw telemetry data to be normalized into the security state space."""

    raw_values: dict[str, float] = field(default_factory=dict)
    """Raw sensor/telemetry values keyed by dimension name."""

    events: list[SecurityEvent] = field(default_factory=list)
    """Security events detected in this telemetry window."""

    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class CGAConfig:
    """
    Configuration for the Cyber Genesis Architecture engine.

    Contains all tunable parameters: weights, thresholds, amplification
    factors, and operational constants.
    """

    history_limit: int = 1000
    """Maximum retained assessments and audit events."""

    # --- Genesis Equation weights ---
    alpha: float = 0.25
    """Weight for DR_c^(a) term in the Genesis Equation."""

    beta: float = 0.20
    """Weight for DR_c_dot^(a) term in the Genesis Equation."""

    gamma: float = 0.30
    """Weight for H_c+ term in the Genesis Equation."""

    delta: float = 0.25
    """Weight for CCI_c/Θ_c term in the Genesis Equation."""

    # --- HSA ---
    hsa_amplification: float = 1.5
    """k — threat amplification factor for HSA."""

    hsa_critical_threshold: float = 0.05
    """Threshold for H_c ≈ 0 (CRITICAL zone)."""

    # --- CCI ---
    cci_threshold: float = 1.0
    """Θ_c — cascade collapse threshold."""

    cci_coupling_gamma: float = 0.5
    """γ — coupling strength in CCI computation."""

    # --- DR ---
    dr_weights: np.ndarray = field(
        default_factory=lambda: np.ones(NUM_DIMENSIONS) / NUM_DIMENSIONS
    )
    """Per-dimension weights w_i for DR computation."""

    dr_sigmas: np.ndarray = field(
        default_factory=lambda: np.full(NUM_DIMENSIONS, 0.15)
    )
    """Per-dimension normalization σ_i for DR computation."""

    # --- ULE ---
    ule_capacity: np.ndarray = field(
        default_factory=lambda: np.ones(NUM_DIMENSIONS)
    )
    """Per-dimension security capacity."""

    # --- Domain Nullification ---
    domain_weights: np.ndarray = field(
        default_factory=lambda: np.ones(NUM_DIMENSIONS) / NUM_DIMENSIONS
    )
    """Per-domain weights W_i for domain metric computation."""

    # --- ΔCR ---
    dcr_thresholds: tuple[float, float, float] = (0.0, 0.3, 0.7)
    """ΔCR thresholds for (prepare, contain, emergency)."""

    # --- DSA history ---
    dsa_history_window: int = 20
    """Number of past states to keep for derivative computation."""

    # --- Status thresholds for G_c ---
    status_thresholds: dict[str, float] = field(default_factory=lambda: {
        "PERMITTED": 0.90,
        "MONITORING": 0.70,
        "WARNING": 0.40,
        "CRITICAL": 0.10,
        "CONTAINMENT": 0.0,
    })

    # --- Security buffer ---
    initial_security_buffer: float = 1.0
    """Initial security buffer B_c for HSA computation."""

    buffer_decay_rate: float = 0.02
    """Rate at which buffer decays under sustained divergence."""

    buffer_recovery_rate: float = 0.05
    """Rate at which buffer recovers when divergence decreases."""

    # --- Baseline calibration (Regeneration: observe → rebaseline) ---
    baseline_calibration_ticks: int = 0
    """Warmup ticks used to learn X_c* from observed telemetry (0 = disabled).

    Simulation and attack-injection work against the ideal all-nominal
    baseline. Live hosts never sit at 1.0, so they must learn their own
    reference before divergence means anything.
    """

    baseline_tolerance_sigmas: float = 3.0
    """Envelope half-width in standard deviations of the observed baseline."""

    baseline_min_tolerance: float = 0.1
    """Floor on envelope half-width, so quiet dimensions stay stable."""

    # --- Closed loop (RE-EVAL → SENSE) ---
    closed_loop_enabled: bool = True
    """Apply ENCRYPT/CONVERGE outputs back into SENSE for the next cycle."""

    cascade_gain: float = 0.12
    """How strongly residual divergence propagates through T_c per tick."""

    convergence_gain: float = 0.35
    """How strongly ΔCR actions restore degraded dimensions toward X_c*."""

    regeneration_enabled: bool = True
    """Apply R_genesis projection when recovering inside a controlled HSA zone."""

    # --- Origin attribution (Ψ_c) ---
    origin_trace_enabled: bool = True
    """Attribute each cycle's divergence to a most-likely origin dimension."""

    origin_decay: float = 0.6
    """Per-hop attenuation when building a cascade signature."""

    origin_depth: int = 3
    """Cascade hops included in a signature."""

    # --- Cascade coherence (Λ_c) ---
    coherence_enabled: bool = True
    """Grade T_c's prediction against the state's actual motion each tick."""

    coupling_adaptation_rate: float = 0.0
    """Correct T_c from coherence misses (0 = keep the authored matrix fixed).

    Left off by default: the authored coupling encodes intent, and letting a
    live host rewrite it changes what the cascade math means.
    """

    # --- Scope cost (K_c) ---
    nullification_cost_enabled: bool = True
    """Price each dimension's blind spot before it may be nullified."""

    max_nullification_cost: float = 0.05
    """Ceiling on the visibility a single auto-nullification may forfeit."""

    # --- Permission debt ---
    permission_debt_accrual: float = 0.0
    """Debt added per denied tick (0 = Π_c returns the instant conditions clear).

    Non-zero values stop the permission gate from flapping: after a denial the
    system must stay clean long enough to repay before it is trusted again.
    """

    permission_debt_repayment: float = 0.5
    """Debt repaid per clean tick."""

    permission_debt_max: float = 5.0
    """Ceiling on accumulated debt, bounding how long recovery can take."""

    # --- First Knowledge: the 11 Universal Laws ---
    law_conformance_enabled: bool = True
    """Audit every tick against the 11 Laws and report Φ₀, S_ig and Φ_H11."""

    law_authoritative: bool = False
    """Let a broken Law nullify G_H11 and revoke Π_c, as the framework states.

    The source is unambiguous — governance that does not comply becomes a
    nullifier and existence is refused. It is left off by default because it
    hands a core gate to eleven invariants at once: enable it deliberately,
    after watching the conformance report on your own workload.
    """

    law_violation_tolerance: float = 0.05
    """How far a measured derivative may sit from its required value.

    Below this the Law reads as Stasis. The Laws require exact values (1, 0,
    finite); real telemetry never lands exactly, so conformance needs a band.
    """

    law_boundary_bound: float = 10.0
    """Ceiling on |dΣ/dV| before Law 4's boundary counts as blurred.

    Law 4 requires a finite, sharp edge; in H¹¹ physics an infinity is the
    signature of a failed calculation, so the check is for divergence rather
    than for a target value.
    """

    def __post_init__(self) -> None:
        if not isinstance(self.history_limit, int) or self.history_limit < 1:
            raise ValueError("history_limit must be a positive integer")
        self.dr_weights = np.asarray(self.dr_weights, dtype=np.float64)
        self.dr_sigmas = np.asarray(self.dr_sigmas, dtype=np.float64)
        self.ule_capacity = np.asarray(self.ule_capacity, dtype=np.float64)
        self.domain_weights = np.asarray(self.domain_weights, dtype=np.float64)
