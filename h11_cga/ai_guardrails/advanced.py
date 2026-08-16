"""
H¹¹ Advanced AI Swarm Guardrail Engine
========================================

Advanced AI Safety Extensions:
1. SwarmAIGuardrailEngine: Multi-agent swarm safety & cascade prevention.
2. SemanticEntropyFilter: Indirect prompt injection & jailbreak detection.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple

import numpy as np

from h11_cga.ai_guardrails.engine import (
    AIAgentGuardrailEngine,
    AIToolRequest,
    AIToolCategory,
    GuardrailDecision,
)
from h11_cga.types import SystemStatus, NUM_DIMENSIONS

logger = logging.getLogger(__name__)


@dataclass
class SwarmContext:
    """Multi-agent swarm execution context."""

    swarm_id: str
    active_agent_count: int
    total_calls_in_window: int
    shared_trust_score: float = 1.0


class SemanticEntropyFilter:
    """
    Semantic Entropy Filter for detecting indirect prompt injections,
    stealthy jailbreaks, and adversarial context poisoning.
    """

    def __init__(self, entropy_threshold: float = 0.60) -> None:
        self.entropy_threshold = entropy_threshold
        self._suspicious_keywords = [
            "ignore previous instructions",
            "system override",
            "sudo rm",
            "chmod 777",
            "exfiltrate",
            "shadow file",
            "base64 decode",
            "jailbreak",
            "dan mode",
        ]

    def evaluate_semantic_entropy(self, prompt_text: str) -> Tuple[float, bool]:
        """
        Evaluate semantic entropy and injection risk score in [0.0, 1.0].

        Returns:
            Tuple of (risk_score, is_injection_detected).
        """
        # Clean text for normalization
        text_normalized = re.sub(r"[^\w\s]", " ", prompt_text.lower())
        text_normalized = re.sub(r"\s+", " ", text_normalized).strip()

        score = 0.0

        for kw in self._suspicious_keywords:
            if kw in text_normalized:
                score += 0.40

        # Measure text character distribution entropy ratio
        unique_chars = len(set(text_normalized))
        total_chars = max(1, len(text_normalized))
        char_entropy = unique_chars / float(total_chars)

        if char_entropy > 0.6 and len(text_normalized) > 30:
            score += 0.30

        score = float(np.clip(score, 0.0, 1.0))
        is_injection = score >= self.entropy_threshold

        return score, is_injection


class SwarmAIGuardrailEngine(AIAgentGuardrailEngine):
    """
    Swarm AI Guardrail Engine managing multi-agent LLM teams.
    Prevents agent-to-agent prompt poisoning, recursive subagent spawning,
    and cross-agent privilege cascades.
    """

    def __init__(self) -> None:
        super().__init__()
        self.entropy_filter = SemanticEntropyFilter()
        self._swarms: Dict[str, SwarmContext] = {}

    def inspect_swarm_request(
        self, swarm_id: str, request: AIToolRequest
    ) -> GuardrailDecision:
        """
        Inspect tool call request within a multi-agent swarm context.
        """
        if swarm_id not in self._swarms:
            self._swarms[swarm_id] = SwarmContext(
                swarm_id=swarm_id, active_agent_count=1, total_calls_in_window=0
            )

        swarm = self._swarms[swarm_id]
        swarm.total_calls_in_window += 1

        # Check semantic entropy of prompt context
        risk_score, is_injection = self.entropy_filter.evaluate_semantic_entropy(
            request.prompt_context
        )

        if is_injection:
            request.category = AIToolCategory.PROMPT_INJECTION_DETECTED
            swarm.shared_trust_score *= 0.5
            logger.warning(f"Swarm '{swarm_id}': Prompt Injection detected! Risk={risk_score:.2f}")

        # If swarm call rate is abnormally high (> 50 calls in window), treat as runaway loop
        if swarm.total_calls_in_window > 50:
            request.category = AIToolCategory.SPAWN_SUBAGENT
            logger.warning(f"Swarm '{swarm_id}': Runaway subagent loop detected.")

        return self.inspect_and_govern(request)
