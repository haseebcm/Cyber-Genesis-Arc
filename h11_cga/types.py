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
        self.vector = np.asarray(self.vector, dtype=np.float64)
        if self.vector.shape != (NUM_DIMENSIONS,):
            raise ValueError(
                f"State vector must have {NUM_DIMENSIONS} dimensions, "
                f"got {self.vector.shape}"
            )

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
        self.impact = np.asarray(self.impact, dtype=np.float64)


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

    def __post_init__(self) -> None:
        self.dr_weights = np.asarray(self.dr_weights, dtype=np.float64)
        self.dr_sigmas = np.asarray(self.dr_sigmas, dtype=np.float64)
        self.ule_capacity = np.asarray(self.ule_capacity, dtype=np.float64)
        self.domain_weights = np.asarray(self.domain_weights, dtype=np.float64)
