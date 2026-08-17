from __future__ import annotations

from h11_cga.types import (
    SecurityState, SecurityBaseline, SecurityOrigin,
    DivergenceResult, DivergenceClassification,
    DomainVector, CascadePath, OriginHypothesis,
    HSAZone, SystemStatus,
    ActionType, ActionUrgency, ResponseAction,
    ThreatAssessment, SecurityEvent, TelemetryInput,
    CGAConfig, EncryptICClassification,
    NUM_DIMENSIONS, DIMENSION_NAMES, DIMENSION_INDEX,
    NUM_TRANSFORMATION_NODES,
)
from h11_cga.orchestrator import CyberGenesisEngine
from h11_cga.core.transformation_matrix import TransformationMatrix
from h11_cga.core.cyber_genesis_equation import CyberGenesisEquation
from h11_cga.core.advanced import (
    StateIntegrityProver,
    SelfHealingProjector,
    DynamicCouplingEngine,
)
from h11_cga.core.origin import OriginTracer
from h11_cga.core.coherence import CoherenceAuditor

from h11_cga.adapters import (
    BaseTelemetryAdapter,
    SystemAdapter,
    KubernetesAdapter,
    EBPFNetworkProbe,
    LogAdapter,
    TelemetryIngestionHub,
)
from h11_cga.adapters.hardware_accel import (
    XDPKernelDropEngine,
    ProcessQuarantineEngine,
)

from h11_cga.ai_guardrails import (
    AIAgentGuardrailEngine,
    AIToolRequest,
    AIToolCategory,
    GuardrailDecision,
)
from h11_cga.ai_guardrails.advanced import (
    SwarmAIGuardrailEngine,
    SemanticEntropyFilter,
)

from h11_cga.benchmarks import (
    RedTeamBenchmarkEngine,
    ScenarioResult,
    BenchmarkReport,
)
from h11_cga.license import (
    LicenseManager,
    LicenseTier,
    FeatureFlag,
)

from h11_cga.server import (
    ControlPlaneServer,
)

__version__ = '3.0.0-REFLEXIVE'

__all__ = [
    'SecurityState',
    'SecurityBaseline',
    'SecurityOrigin',
    'DivergenceResult',
    'DivergenceClassification',
    'DomainVector',
    'CascadePath',
    'OriginHypothesis',
    'HSAZone',
    'SystemStatus',
    'ActionType',
    'ActionUrgency',
    'ResponseAction',
    'ThreatAssessment',
    'SecurityEvent',
    'TelemetryInput',
    'CGAConfig',
    'EncryptICClassification',
    'NUM_DIMENSIONS',
    'DIMENSION_NAMES',
    'DIMENSION_INDEX',
    'NUM_TRANSFORMATION_NODES',
    'CyberGenesisEngine',
    'TransformationMatrix',
    'CyberGenesisEquation',
    'StateIntegrityProver',
    'SelfHealingProjector',
    'DynamicCouplingEngine',
    'OriginTracer',
    'CoherenceAuditor',
    'BaseTelemetryAdapter',
    'SystemAdapter',
    'KubernetesAdapter',
    'EBPFNetworkProbe',
    'LogAdapter',
    'TelemetryIngestionHub',
    'XDPKernelDropEngine',
    'ProcessQuarantineEngine',
    'AIAgentGuardrailEngine',
    'AIToolRequest',
    'AIToolCategory',
    'GuardrailDecision',
    'SwarmAIGuardrailEngine',
    'SemanticEntropyFilter',
    'RedTeamBenchmarkEngine',
    'ScenarioResult',
    'BenchmarkReport',
    'LicenseManager',
    'LicenseTier',
    'FeatureFlag',
    'ControlPlaneServer',
]
