"""
H¹¹-CGA AI Agent Safety Guardrail Engine
==========================================

State-space guardrail governance engine for Autonomous AI Agents and LLM tool loops.
Enforces H¹¹ Genesis permission controls and nullifies unauthorized tool calls (N_0).
"""

from __future__ import annotations

import enum
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable

import numpy as np

from h11_cga.orchestrator import CyberGenesisEngine
from h11_cga.types import (
    SecurityEvent,
    SecurityState,
    SystemStatus,
    ThreatAssessment,
    NUM_DIMENSIONS,
    DIMENSION_NAMES,
    DIMENSION_INDEX,
)

logger = logging.getLogger(__name__)


class AIToolCategory(enum.Enum):
    """Categories of tool execution requests from AI Agents."""

    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    CODE_EXECUTION = "CODE_EXECUTION"
    DATABASE_QUERY = "DATABASE_QUERY"
    NETWORK_REQUEST = "NETWORK_REQUEST"
    PRIVILEGED_CMD = "PRIVILEGED_CMD"
    SPAWN_SUBAGENT = "SPAWN_SUBAGENT"
    PROMPT_INJECTION_DETECTED = "PROMPT_INJECTION_DETECTED"


@dataclass
class AIToolRequest:
    """A proposed tool or function execution request from an AI agent."""

    agent_id: str
    tool_name: str
    category: AIToolCategory
    parameters: Dict[str, Any] = field(default_factory=dict)
    prompt_context: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class GuardrailDecision:
    """Result of the H¹¹-CGA AI Guardrail inspection."""

    permitted: bool
    status: SystemStatus
    genesis_value: float
    nullified: bool
    reason: str
    proposed_impact: np.ndarray
    assessment: ThreatAssessment
    timestamp: float = field(default_factory=time.time)


class AIAgentGuardrailEngine:
    """
    H¹¹-CGA AI Agent Runtime Guardrail Engine.

    Intercepts AI agent tool call requests, projects their impact onto the
    11-dimensional MCC Security State Vector, and evaluates Genesis Permission
    before permitting execution. If permission is revoked (Π_c = 0), Encrypt-IC
    nullifies execution (N_0).
    """

    def __init__(self, cga_engine: Optional[CyberGenesisEngine] = None) -> None:
        self.engine = cga_engine if cga_engine is not None else CyberGenesisEngine()
        self._blocked_requests: List[AIToolRequest] = []
        self._permitted_requests: List[AIToolRequest] = []

    def map_request_to_impact(self, request: AIToolRequest) -> np.ndarray:
        """
        Project an AI tool call request onto the 11 MCC security dimensions.

        Dimensions:
            0: Identity, 1: Authorization, 2: Network, 3: Data, 4: Compute,
            5: Memory, 6: Execution, 7: Resource, 8: Trust, 9: Governance, 10: Recovery
        """
        impact = np.zeros(NUM_DIMENSIONS)
        cat = request.category

        if cat == AIToolCategory.FILE_READ:
            impact[3] = -0.05  # Slight Data inspection impact
        elif cat == AIToolCategory.FILE_WRITE:
            impact[3] = -0.25  # Data modification
            impact[9] = -0.10  # Governance
        elif cat == AIToolCategory.CODE_EXECUTION:
            impact[6] = -0.40  # Execution risk
            impact[4] = -0.20  # Compute load
            impact[5] = -0.20  # Memory load
        elif cat == AIToolCategory.DATABASE_QUERY:
            impact[3] = -0.15  # Data query
            impact[7] = -0.10  # Resource load
        elif cat == AIToolCategory.NETWORK_REQUEST:
            impact[2] = -0.30  # Network egress
            impact[1] = -0.15  # Authorization check
        elif cat == AIToolCategory.PRIVILEGED_CMD:
            impact[1] = -0.70  # Severe Authorization risk
            impact[8] = -0.50  # Trust degradation
            impact[9] = -0.40  # Governance breach
        elif cat == AIToolCategory.SPAWN_SUBAGENT:
            impact[4] = -0.25  # Compute load
            impact[6] = -0.25  # Execution load
            impact[8] = -0.20  # Trust distribution
        elif cat == AIToolCategory.PROMPT_INJECTION_DETECTED:
            impact[8] = -0.90  # Severe Trust collapse
            impact[1] = -0.80  # Authorization attack
            impact[9] = -0.70  # Governance attack

        # Adjust for extra parameter risks (e.g. root paths, shell scripts)
        params_str = str(request.parameters).lower()
        if "root" in params_str or "sudo" in params_str or "rm -rf" in params_str:
            impact[1] = -0.85
            impact[6] = -0.85

        return impact

    def inspect_and_govern(self, request: AIToolRequest) -> GuardrailDecision:
        """
        Inspect a proposed AI tool call request and enforce Genesis Permission.

        Returns:
            GuardrailDecision indicating whether the action is PERMITTED or NULLIFIED (N_0).
        """
        now = time.time()
        impact = self.map_request_to_impact(request)

        # Create security event simulating the proposed AI tool call
        event = SecurityEvent(
            event_type=f"ai_tool_{request.tool_name}",
            source=f"ai_agent_{request.agent_id}",
            target_dimensions=[i for i, v in enumerate(impact) if v != 0],
            impact=impact,
            severity=float(np.abs(np.min(impact))),
            metadata={
                "agent_id": request.agent_id,
                "tool_name": request.tool_name,
                "category": request.category.value,
            },
            timestamp=now,
        )

        # Run tick with injected event to project state transition
        assessment = self.engine.inject_event(event)

        # Check Genesis Permission Π_c and System Status
        permission = assessment.permission
        status = assessment.status
        gc = assessment.genesis_value

        permitted = (permission == 1.0) and (status != SystemStatus.EMERGENCY) and (status != SystemStatus.CONTAINMENT)

        if permitted:
            self._permitted_requests.append(request)
            reason = f"Tool '{request.tool_name}' permitted under H11 Genesis controls (G_c={gc:.4f})."
            nullified = False
            logger.info(f"AI Guardrail PERMITTED: Agent '{request.agent_id}' tool '{request.tool_name}'.")
        else:
            self._blocked_requests.append(request)
            reason = (
                f"Tool '{request.tool_name}' BLOCKED & NULLIFIED (N_0): "
                f"Genesis Permission revoked (Pi_c={permission}, Status={status.value}, G_c={gc:.4f})."
            )
            nullified = True
            logger.warning(f"AI Guardrail NULLIFIED (N_0): Agent '{request.agent_id}' tool '{request.tool_name}'.")

        return GuardrailDecision(
            permitted=permitted,
            status=status,
            genesis_value=gc,
            nullified=nullified,
            reason=reason,
            proposed_impact=impact,
            assessment=assessment,
            timestamp=now,
        )

    def execute_guarded(
        self, request: AIToolRequest, tool_fn: Callable[..., Any]
    ) -> Any:
        """
        Wrapper to execute a tool function if and only if permitted by H¹¹-CGA.

        Raises:
            PermissionError if the tool call is revoked and nullified (N_0).
        """
        decision = self.inspect_and_govern(request)

        if not decision.permitted:
            raise PermissionError(
                f"H11-CGA Encrypt-IC Rejection: {decision.reason}"
            )

        return tool_fn(**request.parameters)
