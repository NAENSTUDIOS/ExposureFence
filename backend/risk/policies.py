"""
ExposureFence — Versioned Contextual Risk Policies
Provides versioned deterministic scoring algorithms with explainable component breakdowns.
"""

from typing import Any, Dict, Tuple
from backend.intelligence.models import FindingSeverity


def calculate_severity_from_score(score: float) -> FindingSeverity:
    if score >= 90.0:
        return FindingSeverity.CRITICAL
    elif score >= 70.0:
        return FindingSeverity.HIGH
    elif score >= 40.0:
        return FindingSeverity.MEDIUM
    elif score > 0.0:
        return FindingSeverity.LOW
    return FindingSeverity.INFORMATIONAL


class RiskPolicyV1:
    """Legacy scoring policy based on static vulnerability mappings."""
    VERSION = "1.0.0"

    @classmethod
    def evaluate(cls, finding_type: str) -> Tuple[float, FindingSeverity, Dict[str, float]]:
        score = 0.0
        if "S3" in finding_type.upper():
            score = 90.0
        elif "SSH" in finding_type.upper() or "SG" in finding_type.upper():
            score = 80.0
        elif "IAM" in finding_type.upper():
            score = 75.0
        else:
            score = 50.0

        severity = calculate_severity_from_score(score)
        breakdown = {"base_mapping": score}
        return score, severity, breakdown


class RiskPolicyV2:
    """
    Production-grade multi-factor contextual risk policy.
    Evaluates:
      - Asset Criticality (0-100) * 0.25
      - Internet Exposure (0-100) * 0.25
      - Reachability / Attack Path (0-100) * 0.20
      - IAM Privilege Level (0-100) * 0.15
      - Blast Radius Impact (0-100) * 0.15
      - Modifiers: Integrity factor (1.0 or 0.0), Freshness decay (1.0 to 0.7)
    """
    VERSION = "2.0.0"

    @classmethod
    def evaluate(
        cls,
        criticality: float = 50.0,
        exposure: float = 0.0,
        reachability: float = 0.0,
        iam_privilege: float = 0.0,
        blast_radius: float = 0.0,
        integrity_status: str = "VERIFIED",
        freshness_status: str = "FRESH"
    ) -> Tuple[float, FindingSeverity, Dict[str, float]]:
        # Compute base multi-factor score
        w_crit = max(0.0, min(100.0, criticality)) * 0.25
        w_expo = max(0.0, min(100.0, exposure)) * 0.25
        w_reach = max(0.0, min(100.0, reachability)) * 0.20
        w_iam = max(0.0, min(100.0, iam_privilege)) * 0.15
        w_blast = max(0.0, min(100.0, blast_radius)) * 0.15

        base_score = w_crit + w_expo + w_reach + w_iam + w_blast

        # Modifier factors
        integrity_multiplier = 1.0
        if integrity_status == "INTEGRITY_MISMATCH":
            # Tampered evidence drops trust completely
            integrity_multiplier = 0.0
        elif integrity_status != "VERIFIED":
            integrity_multiplier = 0.5

        freshness_multiplier = 1.0
        if freshness_status == "STALE":
            freshness_multiplier = 0.7

        final_score = base_score * integrity_multiplier * freshness_multiplier
        final_score = round(max(0.0, min(100.0, final_score)), 1)
        severity = calculate_severity_from_score(final_score)

        breakdown = {
            "asset_criticality_contribution": round(w_crit, 1),
            "internet_exposure_contribution": round(w_expo, 1),
            "network_reachability_contribution": round(w_reach, 1),
            "iam_privilege_contribution": round(w_iam, 1),
            "blast_radius_contribution": round(w_blast, 1),
            "integrity_multiplier": integrity_multiplier,
            "freshness_multiplier": freshness_multiplier,
            "raw_base_score": round(base_score, 1)
        }

        return final_score, severity, breakdown
