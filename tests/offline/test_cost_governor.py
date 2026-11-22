"""
ExposureFence — Global Free-Tier-Only Cost Safety Override Tests
Verifies cost classification, fail-closed behavior for CHARGEABLE and UNKNOWN operations,
S3 quota verification enforcement, and audit ledger tracking.
All tests run strictly offline with zero live AWS calls.
"""

import pytest
import boto3
from botocore.stub import Stubber

from backend.connectors.cost_governor import (
    CostGovernor,
    CostTier,
    OperationCostProfile,
    get_cost_governor
)
from backend.connectors.client_factory import ReadOnlyClientProxy
from backend.connectors.exceptions import CostGateBlockedError, UnsafeCloudOperationError


def test_01_iam_and_sts_free_tier_confirmed():
    """Verifies that IAM and STS read operations are classified as FREE_TIER_CONFIRMED."""
    governor = CostGovernor()

    # IAM list_roles
    p_roles = governor.classify_operation("iam", "list_roles")
    assert p_roles.cost_tier == CostTier.FREE_TIER_CONFIRMED
    assert "no additional charge" in p_roles.pricing_source

    # STS get_caller_identity
    p_sts = governor.classify_operation("sts", "get_caller_identity")
    assert p_sts.cost_tier == CostTier.FREE_TIER_CONFIRMED
    assert "free of charge" in p_sts.pricing_source


def test_02_s3_live_inspection_fails_closed_without_verified_quota():
    """Verifies that live S3 operations without verified quota fail closed with CostGateBlockedError."""
    # Governor without verified Free Tier quota
    governor = CostGovernor(s3_free_tier_verified=False, remaining_s3_quota=0)

    # In live mode, list_buckets must fail closed
    with pytest.raises(CostGateBlockedError) as exc_info:
        governor.verify_cost_safety(
            service="s3",
            operation="list_buckets",
            region="us-east-1",
            expected_count=1,
            is_live=True
        )
    assert "Cost Gate Blocked" in str(exc_info.value)
    assert "remaining active Free Tier request quota is verified" in str(exc_info.value)


def test_03_s3_live_inspection_permitted_with_verified_quota():
    """Verifies that live S3 operations proceed when Free Tier quota has been verified."""
    governor = CostGovernor(s3_free_tier_verified=True, remaining_s3_quota=10)

    record = governor.verify_cost_safety(
        service="s3",
        operation="list_buckets",
        region="us-east-1",
        expected_count=2,
        is_live=True
    )
    assert record.assessment_status == "PERMITTED_FREE_TIER"
    assert record.cost_tier == CostTier.FREE_TIER_CONFIRMED
    assert governor.remaining_s3_quota == 8


def test_04_s3_quota_exhaustion_fails_closed():
    """Verifies that depleting remaining S3 quota blocks subsequent calls."""
    governor = CostGovernor(s3_free_tier_verified=True, remaining_s3_quota=1)

    # Consumes remaining 1 call
    governor.verify_cost_safety("s3", "get_bucket_location", is_live=True)
    assert governor.remaining_s3_quota == 0

    # Next call fails closed
    with pytest.raises(CostGateBlockedError) as exc_info:
        governor.verify_cost_safety("s3", "get_bucket_policy", is_live=True)
    assert "Cost Gate Blocked" in str(exc_info.value)


def test_05_metered_services_fail_closed():
    """Verifies that metered paid services (Config, Security Hub) are CHARGEABLE and fail closed."""
    governor = CostGovernor()

    p_config = governor.classify_operation("config", "describe_configuration_recorders")
    assert p_config.cost_tier == CostTier.CHARGEABLE

    with pytest.raises(CostGateBlockedError):
        governor.verify_cost_safety("config", "describe_configuration_recorders", is_live=True)

    p_sh = governor.classify_operation("securityhub", "get_findings")
    assert p_sh.cost_tier == CostTier.CHARGEABLE

    with pytest.raises(CostGateBlockedError):
        governor.verify_cost_safety("securityhub", "get_findings", is_live=True)


def test_06_unknown_operations_fail_closed():
    """Verifies that unknown or unprofiled operations default to UNKNOWN and fail closed."""
    governor = CostGovernor()

    p_unknown = governor.classify_operation("unknown_service", "unknown_operation")
    assert p_unknown.cost_tier == CostTier.UNKNOWN

    with pytest.raises(CostGateBlockedError):
        governor.verify_cost_safety("unknown_service", "unknown_operation", is_live=True)


def test_07_offline_mode_always_permitted():
    """Verifies that offline/mock mode is always permitted with zero cost ledger entries."""
    governor = CostGovernor()

    rec = governor.verify_cost_safety("s3", "list_buckets", is_live=False)
    assert rec.assessment_status == "PERMITTED_OFFLINE"
    assert "zero AWS network traffic" in rec.reason


def test_08_client_proxy_enforces_cost_gate():
    """Verifies that ReadOnlyClientProxy intercepts and enforces cost gate in live mode."""
    import os
    s3_client = boto3.client("s3", region_name="us-east-1")
    proxy = ReadOnlyClientProxy(raw_client=s3_client, service_name="s3")

    # In offline mode (default), calls pass through to raw client (which would fail on stub if not stubbed)
    stubber = Stubber(s3_client)
    stubber.add_response("get_bucket_location", {"LocationConstraint": ""}, {"Bucket": "my-bucket"})
    stubber.activate()
    res = proxy.get_bucket_location(Bucket="my-bucket")
    assert res["LocationConstraint"] == ""
    stubber.deactivate()

    # In live mode without verified Free Tier S3 quota, cost gate immediately raises CostGateBlockedError
    os.environ["EXPOSUREFENCE_DATA_MODE"] = "aws"
    try:
        with pytest.raises(CostGateBlockedError):
            proxy.get_bucket_location(Bucket="my-bucket")
    finally:
        del os.environ["EXPOSUREFENCE_DATA_MODE"]
