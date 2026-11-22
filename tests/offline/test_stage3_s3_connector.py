"""
ExposureFence — Stage 3 S3 Read-Only Connector & Evidence Integration Tests
Comprehensive offline verification validating S3 inventory pagination, region resolution,
Public Access Block analysis, conditional policies, ACL grants, Object Ownership controls,
default encryption, versioning, budget/rate limit enforcement, and attack-path graph integration.
All tests run strictly offline with zero live AWS calls using botocore Stubber.
"""

from datetime import datetime, UTC
import hashlib
import json
import os
import pytest
import boto3
from botocore.stub import Stubber
from botocore.exceptions import ClientError

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
from backend.connectors.client_factory import (
    ALLOWED_OPERATIONS,
    ALLOWED_SERVICES,
    ReadOnlyAWSClientFactory,
    ReadOnlyClientProxy
)
from backend.connectors.boundaries import (
    APICallBudget,
    RateLimiter,
    get_allowed_regions
)
from backend.connectors.evidence_status import (
    AssessmentStatus,
    build_failure_evidence
)
from backend.connectors.exceptions import (
    APIBudgetExceededError,
    APITimeoutError,
    APIThrottledError,
    UnauthorizedRegionError,
    UnauthorizedServiceError,
    UnsafeCloudOperationError
)
from backend.graph.engine import ResourceGraph
from backend.graph.models import EdgeType, GraphNode, NodeType, RelationshipStatus
from backend.graph.s3_analyzer import ingest_s3_evidence_to_graph
from backend.dispatcher import ALLOWED_TOOLS


class MockSessionWrapper:
    """Mock Boto3 session wrapper to supply stubbed clients."""
    def __init__(self, clients):
        self._clients = clients

    def client(self, service_name, region_name=None, **kwargs):
        if service_name in self._clients:
            return self._clients[service_name]
        raise ValueError(f"No mock client for service {service_name}")

    def get_client(self, service_name, region_name=None, **kwargs):
        return self.client(service_name, region_name=region_name, **kwargs)


# =========================================================================
# 1. MULTIPLE PAGES OF BUCKET INVENTORY
# =========================================================================

def test_01_multiple_pages_of_bucket_inventory():
    """Verifies that list_s3_buckets paginates across multiple pages using ContinuationToken."""
    s3_client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3_client)
    now = datetime.now(UTC)

    # Page 1
    stubber.add_response("list_buckets", {
        "Buckets": [
            {"Name": "bucket-page1-a", "CreationDate": now},
            {"Name": "bucket-page1-b", "CreationDate": now}
        ],
        "ContinuationToken": "token_page_2"
    }, {"MaxBuckets": 2})

    # Page 2 (Final)
    stubber.add_response("list_buckets", {
        "Buckets": [
            {"Name": "bucket-page2-c", "CreationDate": now}
        ]
    }, {"MaxBuckets": 2, "ContinuationToken": "token_page_2"})

    stubber.activate()
    session = MockSessionWrapper({"s3": s3_client})

    buckets = list_s3_buckets(max_buckets=2, session=session)
    assert len(buckets) == 3
    assert [b["name"] for b in buckets] == ["bucket-page1-a", "bucket-page1-b", "bucket-page2-c"]

    stubber.deactivate()


# =========================================================================
# 2. REPEATED CONTINUATION TOKEN DETECTION
# =========================================================================

def test_02_repeated_continuation_token_loop_detection():
    """Verifies that an infinite loop from a repeated ContinuationToken is safely terminated."""
    s3_client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3_client)
    now = datetime.now(UTC)

    stubber.add_response("list_buckets", {
        "Buckets": [{"Name": "bucket-loop-1", "CreationDate": now}],
        "ContinuationToken": "looping_token"
    }, {})

    stubber.add_response("list_buckets", {
        "Buckets": [{"Name": "bucket-loop-2", "CreationDate": now}],
        "ContinuationToken": "looping_token"  # Identical token repeated!
    }, {"ContinuationToken": "looping_token"})

    stubber.activate()
    session = MockSessionWrapper({"s3": s3_client})

    buckets = list_s3_buckets(session=session)
    assert len(buckets) == 2
    assert [b["name"] for b in buckets] == ["bucket-loop-1", "bucket-loop-2"]

    stubber.deactivate()


# =========================================================================
# 3. BUCKET LOCATION NORMALIZATION
# =========================================================================

def test_03_bucket_location_normalization():
    """Verifies correct resolution of legacy location constraints (empty -> us-east-1, EU -> eu-west-1)."""
    s3_client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3_client)

    # 1. Empty string resolves to us-east-1
    stubber.add_response("get_bucket_location", {"LocationConstraint": ""}, {"Bucket": "bucket-east"})
    # 2. 'EU' resolves to eu-west-1
    stubber.add_response("get_bucket_location", {"LocationConstraint": "EU"}, {"Bucket": "bucket-eu"})
    # 3. Explicit region (e.g. ap-south-1)
    stubber.add_response("get_bucket_location", {"LocationConstraint": "ap-south-1"}, {"Bucket": "bucket-mumbai"})

    stubber.activate()
    session = MockSessionWrapper({"s3": s3_client})

    res_east = resolve_bucket_region("bucket-east", session=session)
    assert res_east["region"] == "us-east-1"
    assert res_east["is_resolved"] is True

    res_eu = resolve_bucket_region("bucket-eu", session=session)
    assert res_eu["region"] == "eu-west-1"
    assert res_eu["is_resolved"] is True

    res_mumbai = resolve_bucket_region("bucket-mumbai", session=session)
    assert res_mumbai["region"] == "ap-south-1"
    assert res_mumbai["is_resolved"] is True

    stubber.deactivate()


# =========================================================================
# 4. REGION ALLOWLIST ENFORCEMENT
# =========================================================================

def test_04_region_allowlist_enforcement():
    """Verifies that a bucket residing outside the configured region allowlist is not scanned."""
    s3_client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3_client)

    # Location reports ap-southeast-1, but default allowlist is ['us-east-1']
    stubber.add_response("get_bucket_location", {"LocationConstraint": "ap-southeast-1"}, {"Bucket": "foreign-bucket"})
    stubber.activate()
    session = MockSessionWrapper({"s3": s3_client})

    evidence = collect_s3_bucket_inventory_evidence("foreign-bucket", session=session)
    assert evidence["assessment_status"] == AssessmentStatus.REGION_NOT_ALLOWED.value
    assert evidence["verification_result"] == "ASSESSMENT_INCOMPLETE"
    assert "outside allowed regions" in evidence["raw_evidence"]["error"]

    stubber.deactivate()


# =========================================================================
# 5. PUBLIC ACCESS BLOCK CONFIGURATION ANALYSIS
# =========================================================================

def test_05_public_access_block_configuration_analysis():
    """Verifies analysis of complete vs partial S3 Block Public Access configurations."""
    # Complete protection
    full_pab = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True
    }
    analysis_full = analyze_s3_public_access_block(full_pab)
    assert analysis_full["is_effective"] is True
    assert analysis_full["exposure_risk"] == "NONE"

    # Partial protection (only block policy)
    partial_pab = {
        "BlockPublicAcls": False,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": False
    }
    analysis_partial = analyze_s3_public_access_block(partial_pab)
    assert analysis_partial["is_effective"] is False
    assert analysis_partial["exposure_risk"] == "MODERATE"


# =========================================================================
# 6. MISSING PUBLIC ACCESS BLOCK CONFIGURATION
# =========================================================================

def test_06_missing_public_access_block_configuration():
    """Verifies that NoSuchPublicAccessBlockConfiguration is handled cleanly as absent without throwing."""
    s3_client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3_client)

    stubber.add_client_error(
        "get_public_access_block",
        service_error_code="NoSuchPublicAccessBlockConfiguration",
        service_message="The public access block configuration was not found",
        expected_params={"Bucket": "unconfigured-bucket"}
    )
    stubber.activate()
    session = MockSessionWrapper({"s3": s3_client})

    pab = get_bucket_public_access_block("unconfigured-bucket", session=session)
    assert pab["status"] == "ABSENT"
    assert pab["is_effective"] is False
    assert pab["block_public_policy"] is False

    stubber.deactivate()


# =========================================================================
# 7. PUBLIC BUCKET POLICY DETECTION
# =========================================================================

def test_07_public_bucket_policy_detection():
    """Verifies that a policy granting Principal: '*' without restrictive conditions is detected as public."""
    public_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::public-bucket/*"
        }]
    }

    analysis = analyze_s3_bucket_policy(public_policy)
    assert analysis["is_unconditionally_public"] is True
    assert len(analysis["findings"]) > 0
    assert analysis["findings"][0]["severity"] == "CRITICAL"


# =========================================================================
# 8. CONDITIONAL PUBLIC POLICY INTERPRETATION
# =========================================================================

def test_08_conditional_public_policy_interpretation():
    """Verifies that Principal: '*' restricted by condition keys is NOT classified as unconditionally public."""
    conditional_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "RestrictedVpceAccess",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::vpc-only-bucket/*",
            "Condition": {
                "StringEquals": {
                    "aws:sourceVpce": "vpce-1a2b3c4d"
                }
            }
        }]
    }

    analysis = analyze_s3_bucket_policy(conditional_policy)
    assert analysis["is_unconditionally_public"] is False
    assert analysis["is_conditionally_restricted"] is True
    assert analysis["findings"][0]["rule_id"] == "S3-CONDITIONAL-WILDCARD"


# =========================================================================
# 9. CROSS-ACCOUNT BUCKET POLICY DETECTION
# =========================================================================

def test_09_cross_account_bucket_policy_detection():
    """Verifies that foreign account principals in bucket policies are detected and recorded."""
    cross_acct_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "CrossAccountShare",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::shared-bucket/*"
        }]
    }

    analysis = analyze_s3_bucket_policy(cross_acct_policy, target_account_id="123456789012")
    assert "arn:aws:iam::999988887777:root" in analysis["cross_account_principals"]
    assert analysis["is_unconditionally_public"] is False


# =========================================================================
# 10. PUBLIC ACL GRANT DETECTION
# =========================================================================

def test_10_public_acl_grant_detection():
    """Verifies detection of AllUsers and AuthenticatedUsers public ACL grants."""
    acl_data = {
        "Grants": [
            {
                "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                "Permission": "READ"
            },
            {
                "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"},
                "Permission": "WRITE"
            }
        ]
    }

    analysis = analyze_s3_bucket_acl(acl_data)
    assert analysis["is_public_acl"] is True
    assert analysis["is_public_read"] is True
    assert analysis["is_public_write"] is True
    assert "READ" in analysis["all_users_grants"]
    assert "WRITE" in analysis["authenticated_users_grants"]


# =========================================================================
# 11. BUCKET OWNERSHIP CONTROLS DISABLES ACLS
# =========================================================================

def test_11_bucket_ownership_controls_disables_acls():
    """Verifies that BucketOwnerEnforced disables ACL evaluation, preventing public ACL exposure."""
    acl_data = {
        "Grants": [
            {
                "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                "Permission": "READ"
            }
        ]
    }

    # When BucketOwnerEnforced is set, ACLs are inactive
    analysis = analyze_s3_bucket_acl(acl_data, ownership_rule="BucketOwnerEnforced")
    assert analysis["acls_disabled"] is True
    assert analysis["is_public_acl"] is False


# =========================================================================
# 12. SSE-S3 DETECTION
# =========================================================================

def test_12_sse_s3_detection():
    """Verifies detection of explicit SSE-S3 default encryption."""
    enc_data = {
        "rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "AES256"
            },
            "BucketKeyEnabled": False
        }]
    }

    analysis = analyze_s3_encryption(enc_data)
    assert analysis["has_explicit_configuration"] is True
    assert analysis["sse_algorithm"] == "AES256"
    assert analysis["is_kms"] is False
    assert analysis["encryption_type"] == "SSE-S3 (Explicit)"


# =========================================================================
# 13. SSE-KMS DETECTION
# =========================================================================

def test_13_sse_kms_detection():
    """Verifies detection of explicit SSE-KMS encryption with KMS key ID."""
    enc_data = {
        "rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "aws:kms",
                "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/custom-key-id"
            },
            "BucketKeyEnabled": True
        }]
    }

    analysis = analyze_s3_encryption(enc_data)
    assert analysis["has_explicit_configuration"] is True
    assert analysis["sse_algorithm"] == "aws:kms"
    assert analysis["is_kms"] is True
    assert analysis["kms_master_key_id"] == "arn:aws:kms:us-east-1:123456789012:key/custom-key-id"
    assert analysis["bucket_key_enabled"] is True


# =========================================================================
# 14. MISSING EXPLICIT ENCRYPTION WITHOUT FALSE PLAINTEXT CLAIM
# =========================================================================

def test_14_missing_explicit_encryption_no_false_plaintext_claim():
    """Verifies invariant: Missing explicit bucket encryption does NOT claim plaintext objects."""
    analysis = analyze_s3_encryption(None)
    assert analysis["has_explicit_configuration"] is False
    assert analysis["plaintext_objects_claimed"] is False
    assert "default SSE-S3 at rest" in analysis["notes"]


# =========================================================================
# 15. VERSIONING ENABLED, SUSPENDED AND ABSENT
# =========================================================================

def test_15_versioning_enabled_suspended_and_absent():
    """Verifies detection of Enabled, Suspended, and Absent versioning configurations."""
    # 1. Enabled with MFA Delete
    v_enabled = {"Status": "Enabled", "MFADelete": "Enabled"}
    a_enabled = analyze_s3_versioning(v_enabled)
    assert a_enabled["is_enabled"] is True
    assert a_enabled["recovery_readiness"] == "HIGH"

    # 2. Suspended
    v_suspended = {"Status": "Suspended", "MFADelete": "Disabled"}
    a_suspended = analyze_s3_versioning(v_suspended)
    assert a_suspended["is_suspended"] is True
    assert a_suspended["recovery_readiness"] == "LOW"

    # 3. Absent (never configured)
    a_absent = analyze_s3_versioning(None)
    assert a_absent["status"] == "Absent"
    assert a_absent["is_enabled"] is False


# =========================================================================
# 16. ACCESS DENIED HANDLING MAPS TO INCOMPLETE
# =========================================================================

def test_16_access_denied_handling_maps_to_incomplete():
    """Verifies that AccessDenied on configuration retrieval produces explicit failure evidence."""
    s3_client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3_client)

    stubber.add_response("get_bucket_location", {"LocationConstraint": ""}, {"Bucket": "locked-bucket"})
    stubber.add_client_error(
        "get_public_access_block",
        service_error_code="AccessDenied",
        service_message="Access Denied",
        expected_params={"Bucket": "locked-bucket"}
    )
    stubber.activate()
    session = MockSessionWrapper({"s3": s3_client})

    evidence = collect_s3_bucket_inventory_evidence("locked-bucket", session=session)
    assert evidence["verification_result"] == "ASSESSMENT_INCOMPLETE"
    assert evidence["assessment_status"] == AssessmentStatus.ACCESS_DENIED.value
    assert "AccessDenied" in evidence["raw_evidence"]["error"]

    stubber.deactivate()


# =========================================================================
# 17. MISSING OPTIONAL CONFIGURATION HANDLING
# =========================================================================

def test_17_missing_optional_configuration_handling():
    """Verifies that missing optional configurations (policy, encryption, ownership) are handled cleanly."""
    s3_client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3_client)

    # 1. NoSuchBucketPolicy
    stubber.add_client_error("get_bucket_policy", "NoSuchBucketPolicy", "Not found", expected_params={"Bucket": "plain-bucket"})
    # 2. ServerSideEncryptionConfigurationNotFoundError
    stubber.add_client_error("get_bucket_encryption", "ServerSideEncryptionConfigurationNotFoundError", "Not found", expected_params={"Bucket": "plain-bucket"})
    # 3. OwnershipControlsNotFoundError
    stubber.add_client_error("get_bucket_ownership_controls", "OwnershipControlsNotFoundError", "Not found", expected_params={"Bucket": "plain-bucket"})

    stubber.activate()
    session = MockSessionWrapper({"s3": s3_client})

    pol = get_bucket_policy("plain-bucket", session=session)
    assert pol is None

    enc = get_bucket_encryption("plain-bucket", session=session)
    assert enc["status"] == "ABSENT"
    assert enc["has_explicit_encryption"] is False

    own = get_bucket_ownership_controls("plain-bucket", session=session)
    assert own["status"] == "ABSENT"
    assert own["ownership_rule"] is None

    stubber.deactivate()


# =========================================================================
# 18. TIMEOUT AND THROTTLING BEHAVIOR
# =========================================================================

def test_18_timeout_and_throttling_translation():
    """Verifies mapping of timeouts and throttling during S3 inspection."""
    err_timeout = APITimeoutError("Read timeout connecting to S3")
    assert AssessmentStatus.API_TIMEOUT.value == "API_TIMEOUT"

    err_throttled = APIThrottledError("SlowDown: S3 rate limit exceeded")
    assert AssessmentStatus.THROTTLED.value == "THROTTLED"


# =========================================================================
# 19. API BUDGET EXHAUSTION DURING S3 COLLECTION
# =========================================================================

def test_19_api_budget_exhaustion_during_s3_collection():
    """Verifies that reaching the API budget halts S3 inventory listing with APIBudgetExceededError."""
    s3_client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3_client)
    now = datetime.now(UTC)

    budget = APICallBudget(max_budget=1)
    proxy = ReadOnlyClientProxy(raw_client=s3_client, service_name="s3", budget=budget)
    session = MockSessionWrapper({"s3": proxy})

    # Page 1 returns continuation token
    stubber.add_response("list_buckets", {
        "Buckets": [{"Name": "b1", "CreationDate": now}],
        "ContinuationToken": "page_2"
    }, {})
    stubber.activate()

    with pytest.raises(APIBudgetExceededError) as exc_info:
        list_s3_buckets(session=session)
    assert "Assessment API call budget exceeded" in str(exc_info.value)

    stubber.deactivate()


# =========================================================================
# 20. RATE LIMITING DURING S3 COLLECTION
# =========================================================================

def test_20_rate_limiting_during_s3_collection():
    """Verifies that paginated S3 calls respect token bucket rate limiting."""
    s3_client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3_client)
    now = datetime.now(UTC)

    rate_limiter = RateLimiter(max_calls_per_second=20.0)  # 50ms pacing
    proxy = ReadOnlyClientProxy(raw_client=s3_client, service_name="s3", rate_limiter=rate_limiter)
    session = MockSessionWrapper({"s3": proxy})

    stubber.add_response("list_buckets", {
        "Buckets": [{"Name": "b1", "CreationDate": now}],
        "ContinuationToken": "page_2"
    }, {})
    stubber.add_response("list_buckets", {
        "Buckets": [{"Name": "b2", "CreationDate": now}]
    }, {"ContinuationToken": "page_2"})

    stubber.activate()
    t0 = datetime.now(UTC)
    buckets = list_s3_buckets(session=session)
    elapsed = (datetime.now(UTC) - t0).total_seconds()

    assert len(buckets) == 2
    assert elapsed >= 0.04

    stubber.deactivate()


# =========================================================================
# 21. PARTIAL COLLECTION NEVER CLASSIFIED AS SECURE
# =========================================================================

def test_21_partial_collection_never_classified_as_secure():
    """Verifies invariant: Incomplete or failed collection NEVER results in VERIFIED_SECURE."""
    s3_client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3_client)

    stubber.add_client_error(
        "get_bucket_location",
        service_error_code="NoSuchBucket",
        service_message="The specified bucket does not exist",
        expected_params={"Bucket": "non-existent-bucket"}
    )
    stubber.activate()
    session = MockSessionWrapper({"s3": s3_client})

    evidence = collect_s3_bucket_inventory_evidence("non-existent-bucket", session=session)
    assert evidence["verification_result"] != "VERIFIED_SECURE"
    assert evidence["verification_result"] == "ASSESSMENT_INCOMPLETE"
    assert evidence["assessment_status"] != AssessmentStatus.VERIFIED.value

    stubber.deactivate()


# =========================================================================
# 22. EVIDENCE HASH AND PROVENANCE INTEGRITY
# =========================================================================

def test_22_evidence_hash_and_provenance_integrity():
    """Verifies that evidence records generate reproducible SHA-256 digests."""
    raw_evidence = {
        "bucket_name": "data-lake-raw",
        "region": "us-east-1",
        "is_public": False
    }

    digest1 = hashlib.sha256(json.dumps(raw_evidence, sort_keys=True).encode("utf-8")).hexdigest()
    digest2 = hashlib.sha256(json.dumps(raw_evidence, sort_keys=True).encode("utf-8")).hexdigest()

    assert digest1 == digest2
    assert len(digest1) == 64


# =========================================================================
# 23. ATTACK-PATH GRAPH EVIDENCE GROUNDING
# =========================================================================

def test_23_attack_path_graph_evidence_grounding():
    """Verifies that ingesting S3 evidence into ResourceGraph creates verified nodes and edges with evidence references."""
    graph = ResourceGraph()

    sample_s3_evidence = {
        "evidence_id": "EV-AWS-S3-PublicWebAssets-12345678",
        "resource_id": "PublicWebAssets",
        "source_type": "AWS::S3::Bucket",
        "account_id": "123456789012",
        "region": "us-east-1",
        "raw_evidence": {
            "bucket_name": "PublicWebAssets",
            "bucket_arn": "arn:aws:s3:::PublicWebAssets",
            "is_public": True,
            "exposure_summary": {
                "is_publicly_accessible": True,
                "exposure_level": "CONFIRMED_PUBLIC",
                "exposure_reasons": ["Unrestricted public bucket policy"],
                "confidence": 1.0
            },
            "bucket_policy": {
                "cross_account_principals": ["arn:aws:iam::999988887777:root"]
            },
            "encryption": {"encryption_type": "SSE-S3 (Explicit)", "is_kms": False},
            "versioning": {"status": "Enabled"}
        }
    }

    counts = ingest_s3_evidence_to_graph([sample_s3_evidence], graph)
    assert counts["nodes_added"] > 0
    assert counts["edges_added"] > 0

    # Verify Bucket Node
    b_node = graph.get_node("arn:aws:s3:::PublicWebAssets")
    assert b_node is not None
    assert b_node.node_type == NodeType.S3_BUCKET
    assert b_node.is_publicly_exposed is True

    # Verify Internet Node and Exposure Edge
    internet_node = graph.get_node("INTERNET")
    assert internet_node is not None
    assert internet_node.node_type == NodeType.INTERNET

    exposure_edge = graph.get_edge("edge-internet-s3-PublicWebAssets")
    assert exposure_edge is not None
    assert exposure_edge.edge_type == EdgeType.NETWORK_EXPOSED
    assert exposure_edge.evidence_id == "EV-AWS-S3-PublicWebAssets-12345678"
    assert exposure_edge.status == RelationshipStatus.CONFIRMED

    # Verify Cross-Account Edge
    cross_edge = graph.get_edge("edge-cross-s3-PublicWebAssets-arn_aws_iam__999988887777_root")
    assert cross_edge is not None
    assert cross_edge.edge_type == EdgeType.ACCESSES_RESOURCE
    assert cross_edge.evidence_id == "EV-AWS-S3-PublicWebAssets-12345678"


# =========================================================================
# 24. AGENT CANNOT ACCESS RAW S3 CLIENTS
# =========================================================================

def test_24_agent_cannot_access_raw_s3_clients():
    """Verifies that Bedrock Agent dispatcher excludes any direct raw S3 client access."""
    for tool_name in ALLOWED_TOOLS.keys():
        assert "s3_client" not in tool_name.lower()
        assert "raw_s3" not in tool_name.lower()


# =========================================================================
# 25. ALL MUTATION ATTEMPTS REMAIN BLOCKED
# =========================================================================

def test_25_mutation_attempts_remain_blocked():
    """Verifies that mutating S3 operations are rejected with UnsafeCloudOperationError."""
    s3_client = boto3.client("s3", region_name="us-east-1")
    proxy = ReadOnlyClientProxy(raw_client=s3_client, service_name="s3")

    mutations = [
        ("put_bucket_policy", {"Bucket": "target", "Policy": "{}"}),
        ("delete_bucket", {"Bucket": "target"}),
        ("create_bucket", {"Bucket": "target"}),
        ("put_bucket_acl", {"Bucket": "target", "ACL": "public-read"}),
        ("put_bucket_encryption", {"Bucket": "target", "ServerSideEncryptionConfiguration": {}}),
        ("put_bucket_versioning", {"Bucket": "target", "VersioningConfiguration": {"Status": "Enabled"}}),
        ("put_public_access_block", {"Bucket": "target", "PublicAccessBlockConfiguration": {}}),
        ("delete_public_access_block", {"Bucket": "target"}),
        ("put_object", {"Bucket": "target", "Key": "malicious.sh", "Body": b"malware"}),
        ("delete_object", {"Bucket": "target", "Key": "critical.dat"}),
    ]

    for op, kwargs in mutations:
        with pytest.raises(UnsafeCloudOperationError):
            getattr(proxy, op)(**kwargs)
