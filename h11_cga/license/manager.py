"""
H¹¹-CGA Open-Core License & Feature Specification Manager
===========================================================

Defines Open-Core Community Tier vs. Commercial Enterprise Tier extensions.
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Set

logger = logging.getLogger(__name__)


class LicenseTier(enum.Enum):
    """License Tiers for H¹¹-CGA Platform."""

    COMMUNITY_OPEN_CORE = "COMMUNITY_OPEN_CORE"
    ENTERPRISE = "ENTERPRISE"
    GOVERNMENT_DEFENSE = "GOVERNMENT_DEFENSE"


class FeatureFlag(enum.Enum):
    """Platform Feature Flags."""

    CORE_MATH_ENGINE = "CORE_MATH_ENGINE"
    MCC_STATE_VECTOR_11D = "MCC_STATE_VECTOR_11D"
    STANDARD_ADAPTERS = "STANDARD_ADAPTERS"
    CLI_MONITOR = "CLI_MONITOR"
    REST_API_SERVER = "REST_API_SERVER"
    WEB_DASHBOARD_UI = "WEB_DASHBOARD_UI"
    AI_AGENT_GUARDRAILS = "AI_AGENT_GUARDRAILS"
    REDTEAM_BENCHMARKS = "REDTEAM_BENCHMARKS"

    # Commercial Enterprise Features
    EBPF_XDP_ZERO_COPY_DROP = "EBPF_XDP_ZERO_COPY_DROP"
    HARDWARE_ENCRYPT_IC_KERNEL = "HARDWARE_ENCRYPT_IC_KERNEL"
    MULTI_CLUSTER_K8S_MESH = "MULTI_CLUSTER_K8S_MESH"
    COMPLIANCE_AUDIT_EXPORTER = "COMPLIANCE_AUDIT_EXPORTER"
    HA_CONTROL_PLANE_CLUSTER = "HA_CONTROL_PLANE_CLUSTER"


@dataclass
class LicenseInfo:
    """License details."""

    licensee: str = "Community Open-Core User"
    tier: LicenseTier = LicenseTier.COMMUNITY_OPEN_CORE
    active_features: Set[FeatureFlag] = field(default_factory=set)


class LicenseManager:
    """
    Open-Core License & Feature Flag Manager for H¹¹-CGA.
    """

    def __init__(self, tier: LicenseTier = LicenseTier.COMMUNITY_OPEN_CORE, licensee: str = "Community User") -> None:
        self.license_info = LicenseInfo(licensee=licensee, tier=tier)
        self._init_tier_features()

    def _init_tier_features(self) -> None:
        """Initialize feature set based on tier."""
        community_features = {
            FeatureFlag.CORE_MATH_ENGINE,
            FeatureFlag.MCC_STATE_VECTOR_11D,
            FeatureFlag.STANDARD_ADAPTERS,
            FeatureFlag.CLI_MONITOR,
            FeatureFlag.REST_API_SERVER,
            FeatureFlag.WEB_DASHBOARD_UI,
            FeatureFlag.AI_AGENT_GUARDRAILS,
            FeatureFlag.REDTEAM_BENCHMARKS,
        }

        self.license_info.active_features = set(community_features)

        if self.license_info.tier in (LicenseTier.ENTERPRISE, LicenseTier.GOVERNMENT_DEFENSE):
            enterprise_features = {
                FeatureFlag.EBPF_XDP_ZERO_COPY_DROP,
                FeatureFlag.HARDWARE_ENCRYPT_IC_KERNEL,
                FeatureFlag.MULTI_CLUSTER_K8S_MESH,
                FeatureFlag.COMPLIANCE_AUDIT_EXPORTER,
                FeatureFlag.HA_CONTROL_PLANE_CLUSTER,
            }
            self.license_info.active_features.update(enterprise_features)

    def is_feature_enabled(self, feature: FeatureFlag) -> bool:
        """Check if a feature is enabled under current license."""
        return feature in self.license_info.active_features

    def get_tier_info(self) -> Dict[str, Any]:
        """Return license metadata dict."""
        return {
            "licensee": self.license_info.licensee,
            "tier": self.license_info.tier.value,
            "total_active_features": len(self.license_info.active_features),
            "features": [f.value for f in self.license_info.active_features],
        }
