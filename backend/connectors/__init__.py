"""
ExposureFence AWS Connectors Package (Phase 3 & Stage 1 Evolution)
Provides read-only, non-mutating inspection utilities, secure credential resolution,
caller account verification, assessment rate budgeting, and credential redaction.
"""

from backend.connectors.account_verifier import (
    validate_account_id_format,
    verify_caller_account
)
from backend.connectors.aws_ec2 import (
    analyze_security_group_ingress,
    collect_ec2_exposure_evidence,
    describe_security_groups
)
from backend.connectors.aws_iam import (
    collect_iam_exposure_evidence,
    collect_iam_role_inventory_evidence,
    collect_iam_user_inventory_evidence,
    get_managed_policy_document,
    get_role_details,
    get_role_policy,
    get_user_details,
    get_user_policy,
    list_attached_role_policies,
    list_attached_user_policies,
    list_iam_roles,
    list_iam_users,
    list_role_policies,
    list_user_policies
)
from backend.connectors.iam_policy_intelligence import (
    analyze_privilege_escalation,
    analyze_trust_policy,
    compute_policy_hash,
    extract_allowed_actions,
    is_wildcard_administrator,
    normalize_policy_document,
    summarize_identity_policies
)
from backend.connectors.aws_s3 import (
    collect_s3_bucket_inventory_evidence,
    collect_s3_exposure_evidence,
    get_bucket_acl,
    get_bucket_encryption,
    get_bucket_ownership_controls,
    get_bucket_policy,
    get_bucket_policy_status,
    get_bucket_public_access_block,
    get_bucket_versioning,
    list_s3_buckets,
    resolve_bucket_region
)
from backend.connectors.s3_security_intelligence import (
    analyze_s3_bucket_acl,
    analyze_s3_bucket_policy,
    analyze_s3_encryption,
    analyze_s3_public_access_block,
    analyze_s3_versioning,
    compute_s3_policy_hash,
    determine_s3_exposure_status,
    normalize_s3_policy_document
)
from backend.connectors.aws_session import (
    get_boto3_session,
    get_data_mode,
    is_aws_mode_enabled
)
from backend.connectors.boundaries import (
    APICallBudget,
    RateLimiter,
    get_allowed_regions,
    validate_region
)
from backend.connectors.client_factory import (
    ALLOWED_OPERATIONS,
    ALLOWED_SERVICES,
    ReadOnlyAWSClientFactory,
    ReadOnlyClientProxy
)
from backend.connectors.evidence_status import (
    AssessmentStatus,
    build_failure_evidence,
    map_error_to_assessment_status
)
from backend.connectors.cost_governor import (
    CostAuditRecord,
    CostGovernor,
    CostTier,
    OperationCostProfile,
    get_cost_governor
)
from backend.connectors.exceptions import (
    AccountMismatchError,
    AccountVerificationError,
    APIBudgetExceededError,
    APIRateLimitExceededError,
    APITimeoutError,
    APIThrottledError,
    AWSConfigurationError,
    AWSConnectorError,
    CostGateBlockedError,
    CredentialsUnavailableError,
    UnauthorizedRegionError,
    UnauthorizedServiceError,
    UnsafeCloudOperationError
)
from backend.connectors.redaction import (
    CredentialRedactionFilter,
    redact_credentials,
    redact_string
)

__all__ = [
    # Core Session & Mode
    "get_boto3_session",
    "get_data_mode",
    "is_aws_mode_enabled",

    # Read-Only Connectors (Roles & Users)
    "list_s3_buckets",
    "resolve_bucket_region",
    "get_bucket_public_access_block",
    "get_bucket_policy_status",
    "get_bucket_acl",
    "get_bucket_policy",
    "get_bucket_encryption",
    "get_bucket_versioning",
    "get_bucket_ownership_controls",
    "collect_s3_bucket_inventory_evidence",
    "collect_s3_exposure_evidence",
    "normalize_s3_policy_document",
    "compute_s3_policy_hash",
    "analyze_s3_public_access_block",
    "analyze_s3_bucket_policy",
    "analyze_s3_bucket_acl",
    "analyze_s3_encryption",
    "analyze_s3_versioning",
    "determine_s3_exposure_status",
    "describe_security_groups",
    "analyze_security_group_ingress",
    "collect_ec2_exposure_evidence",
    "list_iam_roles",
    "get_role_details",
    "list_attached_role_policies",
    "list_role_policies",
    "get_role_policy",
    "list_iam_users",
    "get_user_details",
    "list_attached_user_policies",
    "list_user_policies",
    "get_user_policy",
    "get_managed_policy_document",
    "collect_iam_role_inventory_evidence",
    "collect_iam_user_inventory_evidence",
    "collect_iam_exposure_evidence",
    "normalize_policy_document",
    "compute_policy_hash",
    "extract_allowed_actions",
    "is_wildcard_administrator",
    "analyze_trust_policy",
    "analyze_privilege_escalation",
    "summarize_identity_policies",

    # Stage 1 Security Components
    "ReadOnlyAWSClientFactory",
    "ReadOnlyClientProxy",
    "ALLOWED_SERVICES",
    "ALLOWED_OPERATIONS",
    "verify_caller_account",
    "validate_account_id_format",
    "APICallBudget",
    "RateLimiter",
    "get_allowed_regions",
    "validate_region",
    "redact_credentials",
    "redact_string",
    "CredentialRedactionFilter",
    "AssessmentStatus",
    "map_error_to_assessment_status",
    "build_failure_evidence",

    # Cost Governor (Global Free-Tier-Only Cost Safety Override)
    "CostTier",
    "OperationCostProfile",
    "CostAuditRecord",
    "CostGovernor",
    "get_cost_governor",

    # Exceptions
    "AWSConnectorError",
    "AWSConfigurationError",
    "CredentialsUnavailableError",
    "AccountVerificationError",
    "AccountMismatchError",
    "UnauthorizedRegionError",
    "UnauthorizedServiceError",
    "UnsafeCloudOperationError",
    "APIBudgetExceededError",
    "APIRateLimitExceededError",
    "APITimeoutError",
    "APIThrottledError",
    "CostGateBlockedError",
]
