"""
ExposureFence AWS Connectors Package (Phase 3)
Provides read-only, non-mutating inspection utilities for S3, EC2 Security Groups, and IAM.
"""

from backend.connectors.aws_session import get_boto3_session, get_data_mode, is_aws_mode_enabled
from backend.connectors.aws_s3 import (
    list_s3_buckets,
    get_bucket_public_access_block,
    get_bucket_policy_status,
    get_bucket_acl,
    get_bucket_policy,
    collect_s3_exposure_evidence
)
from backend.connectors.aws_ec2 import (
    describe_security_groups,
    analyze_security_group_ingress,
    collect_ec2_exposure_evidence
)
from backend.connectors.aws_iam import (
    list_iam_roles,
    get_role_details,
    list_attached_role_policies,
    collect_iam_exposure_evidence
)

__all__ = [
    "get_boto3_session",
    "get_data_mode",
    "is_aws_mode_enabled",
    "list_s3_buckets",
    "get_bucket_public_access_block",
    "get_bucket_policy_status",
    "get_bucket_acl",
    "get_bucket_policy",
    "collect_s3_exposure_evidence",
    "describe_security_groups",
    "analyze_security_group_ingress",
    "collect_ec2_exposure_evidence",
    "list_iam_roles",
    "get_role_details",
    "list_attached_role_policies",
    "collect_iam_exposure_evidence",
]
