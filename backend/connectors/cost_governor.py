"""
ExposureFence — Global Free-Tier-Only Cost Safety Override Engine
Enforces strict zero-cost boundary: every AWS connector operation is evaluated
against active Free Tier allowances before execution. CHARGEABLE and UNKNOWN operations
fail closed immediately, guaranteeing ₹0.00 / $0.00 additional project expenditure.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
import logging
import os
from typing import Any, Dict, List, Optional

from backend.connectors.exceptions import CostGateBlockedError

logger = logging.getLogger("exposurefence.connectors.cost_governor")


class CostTier(str, Enum):
    """Cost classification for AWS operations."""
    FREE_TIER_CONFIRMED = "FREE_TIER_CONFIRMED"
    CHARGEABLE = "CHARGEABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class OperationCostProfile:
    """Cost profile and Free Tier quota metadata for an AWS API operation."""
    service: str
    operation: str
    cost_tier: CostTier
    pricing_source: str
    free_tier_allowance: str
    requires_quota_verification: bool = False
    fail_closed_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["cost_tier"] = self.cost_tier.value
        return d


@dataclass
class CostAuditRecord:
    """Audit record capturing an evaluated AWS operation under the Cost Safety policy."""
    timestamp: str
    service: str
    operation: str
    region: str
    expected_request_count: int
    cost_tier: CostTier
    pricing_source: str
    applicable_free_tier_allowance: str
    remaining_quota_verification: str
    assessment_status: str
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["cost_tier"] = self.cost_tier.value
        return d


# Known Operation Cost Profiles
# INVARIANT: Only operations with verified zero incremental cost are FREE_TIER_CONFIRMED.
OPERATION_COST_PROFILES: Dict[str, Dict[str, OperationCostProfile]] = {
    # 1. IAM is always free in AWS with no per-request charges
    "iam": {
        "list_roles": OperationCostProfile(
            service="iam",
            operation="list_roles",
            cost_tier=CostTier.FREE_TIER_CONFIRMED,
            pricing_source="AWS IAM Pricing: IAM identity and access management provided at no additional charge.",
            free_tier_allowance="Always Free (Unlimited read-only identity queries)",
            requires_quota_verification=False
        ),
        "get_role": OperationCostProfile(
            service="iam",
            operation="get_role",
            cost_tier=CostTier.FREE_TIER_CONFIRMED,
            pricing_source="AWS IAM Pricing: IAM identity and access management provided at no additional charge.",
            free_tier_allowance="Always Free",
            requires_quota_verification=False
        ),
        "list_attached_role_policies": OperationCostProfile(
            service="iam",
            operation="list_attached_role_policies",
            cost_tier=CostTier.FREE_TIER_CONFIRMED,
            pricing_source="AWS IAM Pricing: IAM identity and access management provided at no additional charge.",
            free_tier_allowance="Always Free",
            requires_quota_verification=False
        ),
        "list_role_policies": OperationCostProfile(
            service="iam",
            operation="list_role_policies",
            cost_tier=CostTier.FREE_TIER_CONFIRMED,
            pricing_source="AWS IAM Pricing: IAM identity and access management provided at no additional charge.",
            free_tier_allowance="Always Free",
            requires_quota_verification=False
        ),
        "get_role_policy": OperationCostProfile(
            service="iam",
            operation="get_role_policy",
            cost_tier=CostTier.FREE_TIER_CONFIRMED,
            pricing_source="AWS IAM Pricing: IAM identity and access management provided at no additional charge.",
            free_tier_allowance="Always Free",
            requires_quota_verification=False
        ),
        "list_users": OperationCostProfile(
            service="iam",
            operation="list_users",
            cost_tier=CostTier.FREE_TIER_CONFIRMED,
            pricing_source="AWS IAM Pricing: IAM identity and access management provided at no additional charge.",
            free_tier_allowance="Always Free",
            requires_quota_verification=False
        ),
        "get_user": OperationCostProfile(
            service="iam",
            operation="get_user",
            cost_tier=CostTier.FREE_TIER_CONFIRMED,
            pricing_source="AWS IAM Pricing: IAM identity and access management provided at no additional charge.",
            free_tier_allowance="Always Free",
            requires_quota_verification=False
        ),
        "list_attached_user_policies": OperationCostProfile(
            service="iam",
            operation="list_attached_user_policies",
            cost_tier=CostTier.FREE_TIER_CONFIRMED,
            pricing_source="AWS IAM Pricing: IAM identity and access management provided at no additional charge.",
            free_tier_allowance="Always Free",
            requires_quota_verification=False
        ),
        "list_user_policies": OperationCostProfile(
            service="iam",
            operation="list_user_policies",
            cost_tier=CostTier.FREE_TIER_CONFIRMED,
            pricing_source="AWS IAM Pricing: IAM identity and access management provided at no additional charge.",
            free_tier_allowance="Always Free",
            requires_quota_verification=False
        ),
        "get_user_policy": OperationCostProfile(
            service="iam",
            operation="get_user_policy",
            cost_tier=CostTier.FREE_TIER_CONFIRMED,
            pricing_source="AWS IAM Pricing: IAM identity and access management provided at no additional charge.",
            free_tier_allowance="Always Free",
            requires_quota_verification=False
        ),
        "get_policy": OperationCostProfile(
            service="iam",
            operation="get_policy",
            cost_tier=CostTier.FREE_TIER_CONFIRMED,
            pricing_source="AWS IAM Pricing: IAM identity and access management provided at no additional charge.",
            free_tier_allowance="Always Free",
            requires_quota_verification=False
        ),
        "get_policy_version": OperationCostProfile(
            service="iam",
            operation="get_policy_version",
            cost_tier=CostTier.FREE_TIER_CONFIRMED,
            pricing_source="AWS IAM Pricing: IAM identity and access management provided at no additional charge.",
            free_tier_allowance="Always Free",
            requires_quota_verification=False
        )
    },

    # 2. STS GetCallerIdentity is free of charge
    "sts": {
        "get_caller_identity": OperationCostProfile(
            service="sts",
            operation="get_caller_identity",
            cost_tier=CostTier.FREE_TIER_CONFIRMED,
            pricing_source="AWS STS Pricing: GetCallerIdentity requests are free of charge.",
            free_tier_allowance="Always Free",
            requires_quota_verification=False
        )
    },

    # 3. S3 read operations are metered by default ($0.0004/1k requests)
    # Under Global Cost Safety, S3 live operations REQUIRE explicit quota verification.
    # Without verified remaining Free Tier quota, they fail closed as CHARGEABLE / UNKNOWN.
    "s3": {
        "list_buckets": OperationCostProfile(
            service="s3",
            operation="list_buckets",
            cost_tier=CostTier.UNKNOWN,
            pricing_source="AWS S3 Pricing: GET/LIST request fees apply ($0.0004 per 1,000 requests).",
            free_tier_allowance="2,000 GET/LIST requests/month (first 12 months on eligible accounts)",
            requires_quota_verification=True,
            fail_closed_reason="S3 live inspection blocked until remaining active Free Tier request quota is verified."
        ),
        "get_public_access_block": OperationCostProfile(
            service="s3",
            operation="get_public_access_block",
            cost_tier=CostTier.UNKNOWN,
            pricing_source="AWS S3 Pricing: GET request fees apply.",
            free_tier_allowance="2,000 GET requests/month Free Tier",
            requires_quota_verification=True,
            fail_closed_reason="S3 live inspection blocked until remaining active Free Tier request quota is verified."
        ),
        "get_bucket_policy_status": OperationCostProfile(
            service="s3",
            operation="get_bucket_policy_status",
            cost_tier=CostTier.UNKNOWN,
            pricing_source="AWS S3 Pricing: GET request fees apply.",
            free_tier_allowance="2,000 GET requests/month Free Tier",
            requires_quota_verification=True,
            fail_closed_reason="S3 live inspection blocked until remaining active Free Tier request quota is verified."
        ),
        "get_bucket_policy": OperationCostProfile(
            service="s3",
            operation="get_bucket_policy",
            cost_tier=CostTier.UNKNOWN,
            pricing_source="AWS S3 Pricing: GET request fees apply.",
            free_tier_allowance="2,000 GET requests/month Free Tier",
            requires_quota_verification=True,
            fail_closed_reason="S3 live inspection blocked until remaining active Free Tier request quota is verified."
        ),
        "get_bucket_acl": OperationCostProfile(
            service="s3",
            operation="get_bucket_acl",
            cost_tier=CostTier.UNKNOWN,
            pricing_source="AWS S3 Pricing: GET request fees apply.",
            free_tier_allowance="2,000 GET requests/month Free Tier",
            requires_quota_verification=True,
            fail_closed_reason="S3 live inspection blocked until remaining active Free Tier request quota is verified."
        ),
        "get_bucket_location": OperationCostProfile(
            service="s3",
            operation="get_bucket_location",
            cost_tier=CostTier.UNKNOWN,
            pricing_source="AWS S3 Pricing: GET request fees apply.",
            free_tier_allowance="2,000 GET requests/month Free Tier",
            requires_quota_verification=True,
            fail_closed_reason="S3 live inspection blocked until remaining active Free Tier request quota is verified."
        ),
        "get_bucket_encryption": OperationCostProfile(
            service="s3",
            operation="get_bucket_encryption",
            cost_tier=CostTier.UNKNOWN,
            pricing_source="AWS S3 Pricing: GET request fees apply.",
            free_tier_allowance="2,000 GET requests/month Free Tier",
            requires_quota_verification=True,
            fail_closed_reason="S3 live inspection blocked until remaining active Free Tier request quota is verified."
        ),
        "get_bucket_versioning": OperationCostProfile(
            service="s3",
            operation="get_bucket_versioning",
            cost_tier=CostTier.UNKNOWN,
            pricing_source="AWS S3 Pricing: GET request fees apply.",
            free_tier_allowance="2,000 GET requests/month Free Tier",
            requires_quota_verification=True,
            fail_closed_reason="S3 live inspection blocked until remaining active Free Tier request quota is verified."
        ),
        "get_bucket_ownership_controls": OperationCostProfile(
            service="s3",
            operation="get_bucket_ownership_controls",
            cost_tier=CostTier.UNKNOWN,
            pricing_source="AWS S3 Pricing: GET request fees apply.",
            free_tier_allowance="2,000 GET requests/month Free Tier",
            requires_quota_verification=True,
            fail_closed_reason="S3 live inspection blocked until remaining active Free Tier request quota is verified."
        )
    },

    # 4. Metered paid services strictly forbidden
    "config": {
        "describe_configuration_recorders": OperationCostProfile(
            service="config",
            operation="describe_configuration_recorders",
            cost_tier=CostTier.CHARGEABLE,
            pricing_source="AWS Config Pricing: Metered per configuration item recorded.",
            free_tier_allowance="None / Metered",
            requires_quota_verification=True,
            fail_closed_reason="AWS Config is a paid metered service strictly blocked under ₹0.00 cost policy."
        )
    },
    "securityhub": {
        "get_findings": OperationCostProfile(
            service="securityhub",
            operation="get_findings",
            cost_tier=CostTier.CHARGEABLE,
            pricing_source="AWS Security Hub Pricing: Metered per compliance check.",
            free_tier_allowance="None / Metered",
            requires_quota_verification=True,
            fail_closed_reason="AWS Security Hub is a paid metered service strictly blocked under ₹0.00 cost policy."
        )
    }
}


class CostGovernor:
    """
    Central cost safety gatekeeper enforcing the Global Free-Tier-Only Cost Safety Override.
    Evaluates every live operation, maintains an audit ledger, and blocks any chargeable
    or unverified operation before execution.
    """

    def __init__(self, s3_free_tier_verified: bool = False, remaining_s3_quota: int = 0):
        self.s3_free_tier_verified = s3_free_tier_verified
        self.remaining_s3_quota = remaining_s3_quota
        self.audit_log: List[CostAuditRecord] = []

    def classify_operation(self, service: str, operation: str) -> OperationCostProfile:
        """Retrieves or synthesizes the cost profile for a given service operation."""
        svc = service.lower().strip()
        op = operation.lower().strip()

        if svc in OPERATION_COST_PROFILES and op in OPERATION_COST_PROFILES[svc]:
            profile = OPERATION_COST_PROFILES[svc][op]
            # Dynamic check for S3 if quota has been verified
            if svc == "s3" and profile.requires_quota_verification and self.s3_free_tier_verified and self.remaining_s3_quota > 0:
                return OperationCostProfile(
                    service=svc,
                    operation=op,
                    cost_tier=CostTier.FREE_TIER_CONFIRMED,
                    pricing_source=profile.pricing_source,
                    free_tier_allowance=f"Active Free Tier Verified (Remaining: {self.remaining_s3_quota})",
                    requires_quota_verification=True
                )
            return profile

        # Unknown operations fail closed
        return OperationCostProfile(
            service=svc,
            operation=op,
            cost_tier=CostTier.UNKNOWN,
            pricing_source="Unverified AWS pricing documentation",
            free_tier_allowance="Unknown",
            requires_quota_verification=True,
            fail_closed_reason=f"Operation '{svc}:{op}' has no confirmed Free Tier allowance and must fail closed."
        )

    def verify_cost_safety(
        self,
        service: str,
        operation: str,
        region: str = "us-east-1",
        expected_count: int = 1,
        is_live: bool = False
    ) -> CostAuditRecord:
        """
        Evaluates an operation under the Cost Safety policy.
        If is_live is True and operation is CHARGEABLE or UNKNOWN, raises CostGateBlockedError.
        """
        profile = self.classify_operation(service, operation)
        timestamp = datetime.now(timezone.utc).isoformat()

        if not is_live:
            # Offline/mock execution is always permitted (₹0.00 spend)
            record = CostAuditRecord(
                timestamp=timestamp,
                service=service,
                operation=operation,
                region=region,
                expected_request_count=expected_count,
                cost_tier=profile.cost_tier,
                pricing_source="Local Offline Execution / Botocore Stubber",
                applicable_free_tier_allowance="Offline Mock (₹0.00 / $0.00)",
                remaining_quota_verification="N/A (Offline)",
                assessment_status="PERMITTED_OFFLINE",
                reason="Executed offline with zero AWS network traffic"
            )
            self.audit_log.append(record)
            return record

        # LIVE EXECUTION GATE
        if profile.cost_tier == CostTier.FREE_TIER_CONFIRMED:
            if profile.requires_quota_verification and self.remaining_s3_quota < expected_count:
                reason = f"Insufficient remaining Free Tier quota ({self.remaining_s3_quota} available, {expected_count} requested)."
                record = CostAuditRecord(
                    timestamp=timestamp,
                    service=service,
                    operation=operation,
                    region=region,
                    expected_request_count=expected_count,
                    cost_tier=CostTier.CHARGEABLE,
                    pricing_source=profile.pricing_source,
                    applicable_free_tier_allowance=profile.free_tier_allowance,
                    remaining_quota_verification="EXHAUSTED",
                    assessment_status="BLOCKED_COST_GATE",
                    reason=reason
                )
                self.audit_log.append(record)
                raise CostGateBlockedError(f"Cost Gate Blocked: {reason}")

            record = CostAuditRecord(
                timestamp=timestamp,
                service=service,
                operation=operation,
                region=region,
                expected_request_count=expected_count,
                cost_tier=CostTier.FREE_TIER_CONFIRMED,
                pricing_source=profile.pricing_source,
                applicable_free_tier_allowance=profile.free_tier_allowance,
                remaining_quota_verification="VERIFIED" if profile.requires_quota_verification else "ALWAYS_FREE",
                assessment_status="PERMITTED_FREE_TIER",
                reason="Confirmed zero incremental cost under active Free Tier"
            )
            if profile.requires_quota_verification:
                self.remaining_s3_quota -= expected_count
            self.audit_log.append(record)
            return record

        # Fail closed on CHARGEABLE or UNKNOWN
        reason = profile.fail_closed_reason or f"Operation '{service}:{operation}' is classified as {profile.cost_tier.value}."
        record = CostAuditRecord(
            timestamp=timestamp,
            service=service,
            operation=operation,
            region=region,
            expected_request_count=expected_count,
            cost_tier=profile.cost_tier,
            pricing_source=profile.pricing_source,
            applicable_free_tier_allowance=profile.free_tier_allowance,
            remaining_quota_verification="UNVERIFIED_OR_CHARGEABLE",
            assessment_status="BLOCKED_COST_GATE",
            reason=reason
        )
        self.audit_log.append(record)
        raise CostGateBlockedError(f"Cost Gate Blocked ({profile.cost_tier.value}): {reason}")


# Global Singleton Cost Governor
GLOBAL_COST_GOVERNOR = CostGovernor()


def get_cost_governor() -> CostGovernor:
    """Retrieves the global CostGovernor singleton."""
    return GLOBAL_COST_GOVERNOR
