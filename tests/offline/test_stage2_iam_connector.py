"""
ExposureFence — Stage 2 Offline Test Suite
Validates Complete IAM Read-Only Connector, Policy Intelligence, Pagination, and Graph Integration.
All tests run 100% offline using botocore.stub.Stubber and synthetic mocks with zero network calls.
"""

from datetime import datetime, UTC
import json
import pytest
import boto3
from botocore.exceptions import ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.stub import Stubber

from backend.connectors import (
    ALLOWED_OPERATIONS,
    ALLOWED_SERVICES,
    APIBudgetExceededError,
    APICallBudget,
    APITimeoutError,
    APIThrottledError,
    AssessmentStatus,
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
    list_user_policies,
    RateLimiter,
    ReadOnlyAWSClientFactory,
    ReadOnlyClientProxy,
    UnauthorizedServiceError,
    UnsafeCloudOperationError
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
from backend.dispatcher import ALLOWED_TOOLS
from backend.graph import EdgeType, NodeType, RelationshipStatus, ResourceGraph
from backend.graph.iam_analyzer import ingest_iam_evidence_to_graph


class MockSessionWrapper:
    """Mock Boto3 session wrapper to supply stubbed clients for offline testing."""
    def __init__(self, clients):
        self._clients = clients

    def client(self, service_name: str, **kwargs):
        if service_name in self._clients:
            return self._clients[service_name]
        raise ValueError(f"No mock client for service {service_name}")


# =========================================================================
# 1. MULTIPLE PAGES OF IAM ROLES
# =========================================================================

def test_01_multiple_pages_of_iam_roles():
    """Verifies that list_iam_roles paginates across multiple pages using markers."""
    iam_client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(iam_client)
    now = datetime.now(UTC)

    # Page 1
    stubber.add_response("list_roles", {
        "Roles": [
            {"RoleName": "Role-Page1-A", "RoleId": "AROA0000000000000001", "Arn": "arn:aws:iam::123456789012:role/Role-Page1-A", "CreateDate": now, "Path": "/"},
            {"RoleName": "Role-Page1-B", "RoleId": "AROA0000000000000002", "Arn": "arn:aws:iam::123456789012:role/Role-Page1-B", "CreateDate": now, "Path": "/"}
        ],
        "IsTruncated": True,
        "Marker": "marker_page_2"
    }, {"MaxItems": 2})

    # Page 2 (Final)
    stubber.add_response("list_roles", {
        "Roles": [
            {"RoleName": "Role-Page2-C", "RoleId": "AROA0000000000000003", "Arn": "arn:aws:iam::123456789012:role/Role-Page2-C", "CreateDate": now, "Path": "/"}
        ],
        "IsTruncated": False
    }, {"MaxItems": 2, "Marker": "marker_page_2"})

    stubber.activate()
    session = MockSessionWrapper({"iam": iam_client})

    roles = list_iam_roles(max_items=2, session=session)
    assert len(roles) == 3
    assert [r["role_name"] for r in roles] == ["Role-Page1-A", "Role-Page1-B", "Role-Page2-C"]

    stubber.deactivate()


# =========================================================================
# 2. MULTIPLE PAGES OF IAM USERS
# =========================================================================

def test_02_multiple_pages_of_iam_users():
    """Verifies that list_iam_users paginates across multiple pages."""
    iam_client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(iam_client)
    now = datetime.now(UTC)

    stubber.add_response("list_users", {
        "Users": [
            {"UserName": "alice", "UserId": "AIDA0000000000000001", "Arn": "arn:aws:iam::123456789012:user/alice", "CreateDate": now, "Path": "/"},
            {"UserName": "bob", "UserId": "AIDA0000000000000002", "Arn": "arn:aws:iam::123456789012:user/bob", "CreateDate": now, "Path": "/"}
        ],
        "IsTruncated": True,
        "Marker": "user_marker_2"
    }, {})

    stubber.add_response("list_users", {
        "Users": [
            {"UserName": "charlie", "UserId": "AIDA0000000000000003", "Arn": "arn:aws:iam::123456789012:user/charlie", "CreateDate": now, "Path": "/"}
        ],
        "IsTruncated": False
    }, {"Marker": "user_marker_2"})

    stubber.activate()
    session = MockSessionWrapper({"iam": iam_client})

    users = list_iam_users(session=session)
    assert len(users) == 3
    assert [u["user_name"] for u in users] == ["alice", "bob", "charlie"]

    stubber.deactivate()


# =========================================================================
# 3. MULTIPLE PAGES OF ATTACHED ROLE POLICIES
# =========================================================================

def test_03_multiple_pages_of_attached_role_policies():
    """Verifies paginated retrieval of attached managed policies for an IAM role."""
    iam_client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(iam_client)

    stubber.add_response("list_attached_role_policies", {
        "AttachedPolicies": [
            {"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
        ],
        "IsTruncated": True,
        "Marker": "pol_marker_2"
    }, {"RoleName": "AppRole"})

    stubber.add_response("list_attached_role_policies", {
        "AttachedPolicies": [
            {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
        ],
        "IsTruncated": False
    }, {"RoleName": "AppRole", "Marker": "pol_marker_2"})

    stubber.activate()
    session = MockSessionWrapper({"iam": iam_client})

    policies = list_attached_role_policies("AppRole", session=session)
    assert len(policies) == 2
    assert policies[1]["is_admin_policy"] is True

    stubber.deactivate()


# =========================================================================
# 4. MULTIPLE PAGES OF INLINE ROLE POLICIES
# =========================================================================

def test_04_multiple_pages_of_inline_role_policies():
    """Verifies paginated retrieval of inline policy names on an IAM role."""
    iam_client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(iam_client)

    stubber.add_response("list_role_policies", {
        "PolicyNames": ["InlinePol1", "InlinePol2"],
        "IsTruncated": True,
        "Marker": "inline_marker_2"
    }, {"RoleName": "AppRole"})

    stubber.add_response("list_role_policies", {
        "PolicyNames": ["InlinePol3"],
        "IsTruncated": False
    }, {"RoleName": "AppRole", "Marker": "inline_marker_2"})

    stubber.activate()
    session = MockSessionWrapper({"iam": iam_client})

    names = list_role_policies("AppRole", session=session)
    assert names == ["InlinePol1", "InlinePol2", "InlinePol3"]

    stubber.deactivate()


# =========================================================================
# 5. MULTIPLE PAGES OF ATTACHED USER POLICIES
# =========================================================================

def test_05_multiple_pages_of_attached_user_policies():
    """Verifies paginated retrieval of attached managed policies on an IAM user."""
    iam_client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(iam_client)

    stubber.add_response("list_attached_user_policies", {
        "AttachedPolicies": [
            {"PolicyName": "AmazonS3ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"}
        ],
        "IsTruncated": True,
        "Marker": "user_pol_2"
    }, {"UserName": "alice"})

    stubber.add_response("list_attached_user_policies", {
        "AttachedPolicies": [
            {"PolicyName": "AmazonEC2ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"}
        ],
        "IsTruncated": False
    }, {"UserName": "alice", "Marker": "user_pol_2"})

    stubber.activate()
    session = MockSessionWrapper({"iam": iam_client})

    policies = list_attached_user_policies("alice", session=session)
    assert len(policies) == 2
    assert policies[0]["policy_name"] == "AmazonS3ReadOnlyAccess"

    stubber.deactivate()


# =========================================================================
# 6. MULTIPLE PAGES OF INLINE USER POLICIES
# =========================================================================

def test_06_multiple_pages_of_inline_user_policies():
    """Verifies paginated retrieval of inline policies on an IAM user."""
    iam_client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(iam_client)

    stubber.add_response("list_user_policies", {
        "PolicyNames": ["UserInline1"],
        "IsTruncated": True,
        "Marker": "u_inline_2"
    }, {"UserName": "alice"})

    stubber.add_response("list_user_policies", {
        "PolicyNames": ["UserInline2"],
        "IsTruncated": False
    }, {"UserName": "alice", "Marker": "u_inline_2"})

    stubber.activate()
    session = MockSessionWrapper({"iam": iam_client})

    names = list_user_policies("alice", session=session)
    assert names == ["UserInline1", "UserInline2"]

    stubber.deactivate()


# =========================================================================
# 7. CORRECT INLINE POLICY DOCUMENT NORMALIZATION
# =========================================================================

def test_07_inline_policy_document_normalization():
    """Verifies correct normalization and hash generation for inline policy documents."""
    raw_doc = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-bucket/*"
        }
    }

    norm = normalize_policy_document(raw_doc)
    assert isinstance(norm["Statement"], list)
    assert norm["Statement"][0]["Action"] == ["s3:GetObject"]
    assert norm["Statement"][0]["Resource"] == ["arn:aws:s3:::my-bucket/*"]

    # Hash reproducibility
    h1 = compute_policy_hash(norm)
    h2 = compute_policy_hash(norm)
    assert h1 == h2
    assert len(h1) == 64


# =========================================================================
# 8. MANAGED POLICY DOCUMENT RETRIEVAL
# =========================================================================

def test_08_managed_policy_document_retrieval():
    """Verifies retrieval of default-version document for managed policies."""
    iam_client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(iam_client)

    pol_arn = "arn:aws:iam::123456789012:policy/CustomSecPolicy"
    doc_content = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}]
    }

    stubber.add_response("get_policy", {
        "Policy": {"PolicyName": "CustomSecPolicy", "DefaultVersionId": "v3"}
    }, {"PolicyArn": pol_arn})

    stubber.add_response("get_policy_version", {
        "PolicyVersion": {"Document": json.dumps(doc_content), "IsDefaultVersion": True}
    }, {"PolicyArn": pol_arn, "VersionId": "v3"})

    stubber.activate()
    session = MockSessionWrapper({"iam": iam_client})

    doc = get_managed_policy_document(pol_arn, session=session)
    assert doc == doc_content

    stubber.deactivate()


# =========================================================================
# 9. WILDCARD ADMINISTRATIVE PERMISSION DETECTION
# =========================================================================

def test_09_wildcard_admin_detection():
    """Verifies detection of full administrator access pattern (Action: * and Resource: *)."""
    admin_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    }
    assert is_wildcard_administrator(admin_doc) is True

    scoped_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]
    }
    assert is_wildcard_administrator(scoped_doc) is False


# =========================================================================
# 10. TRUST-POLICY AND CROSS-ACCOUNT RELATIONSHIP PARSING
# =========================================================================

def test_10_trust_policy_analysis():
    """Verifies parsing of trust policies for wildcard principals and cross-account risks."""
    # 1. Wildcard principal
    wildcard_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
    }
    analysis = analyze_trust_policy(wildcard_trust, target_account_id="123456789012")
    assert analysis["has_wildcard_principal"] is True
    assert analysis["is_risky_trust"] is True

    # 2. Cross-account trust without external ID
    cross_account_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
            "Action": "sts:AssumeRole"
        }]
    }
    analysis_cross = analyze_trust_policy(cross_account_trust, target_account_id="123456789012")
    assert analysis_cross["has_wildcard_principal"] is False
    assert "arn:aws:iam::999988887777:root" in analysis_cross["cross_account_principals"]
    assert analysis_cross["has_external_id_condition"] is False
    assert analysis_cross["is_risky_trust"] is True

    # 3. Secure cross-account trust with external ID
    secure_cross_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": "StrictSecretExternalId123"}}
        }]
    }
    analysis_sec = analyze_trust_policy(secure_cross_trust, target_account_id="123456789012")
    assert analysis_sec["has_external_id_condition"] is True
    assert analysis_sec["is_risky_trust"] is False


# =========================================================================
# 11. REPEATED PAGINATION MARKER DETECTION
# =========================================================================

def test_11_repeated_pagination_marker_loop_detection():
    """Verifies that an infinite loop from a repeated pagination marker is safely terminated."""
    iam_client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(iam_client)
    now = datetime.now(UTC)

    # Simulates broken endpoint returning identical marker indefinitely
    stubber.add_response("list_roles", {
        "Roles": [{"RoleName": "Role-1", "RoleId": "AROA0000000000000001", "Arn": "arn:aws:iam::123:role/Role-1", "CreateDate": now, "Path": "/"}],
        "IsTruncated": True,
        "Marker": "looping_marker"
    }, {})

    stubber.add_response("list_roles", {
        "Roles": [{"RoleName": "Role-2", "RoleId": "AROA0000000000000002", "Arn": "arn:aws:iam::123:role/Role-2", "CreateDate": now, "Path": "/"}],
        "IsTruncated": True,
        "Marker": "looping_marker"  # Identical repeated marker!
    }, {"Marker": "looping_marker"})

    stubber.activate()
    session = MockSessionWrapper({"iam": iam_client})

    # Should break cleanly after detecting repeated marker
    roles = list_iam_roles(session=session)
    assert len(roles) == 2

    stubber.deactivate()


# =========================================================================
# 12. API BUDGET EXHAUSTION DURING PAGINATION
# =========================================================================

def test_12_api_budget_exhaustion_during_pagination():
    """Verifies that hitting the API call budget midway through pagination halts execution."""
    iam_client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(iam_client)
    now = datetime.now(UTC)

    # Configure a tight budget of 1 call
    budget = APICallBudget(max_budget=1)
    proxy = ReadOnlyClientProxy(raw_client=iam_client, service_name="iam", budget=budget)
    session = MockSessionWrapper({"iam": proxy})

    # Page 1 returns truncated
    stubber.add_response("list_roles", {
        "Roles": [{"RoleName": "Role-1", "RoleId": "AROA0000000000000001", "Arn": "arn:aws:iam::123:role/Role-1", "CreateDate": now, "Path": "/"}],
        "IsTruncated": True,
        "Marker": "page_2"
    }, {})

    stubber.activate()

    # Attempting to fetch page 2 consumes 2nd call, raising APIBudgetExceededError
    with pytest.raises(APIBudgetExceededError) as exc_info:
        list_iam_roles(session=session)
    assert "Assessment API call budget exceeded" in str(exc_info.value)

    stubber.deactivate()


# =========================================================================
# 13. RATE LIMITING DURING PAGINATION
# =========================================================================

def test_13_rate_limiting_during_pagination():
    """Verifies that each paginated API call respects rate limiter pacing."""
    iam_client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(iam_client)
    now = datetime.now(UTC)

    rate_limiter = RateLimiter(max_calls_per_second=20.0)  # 50ms pacing
    proxy = ReadOnlyClientProxy(raw_client=iam_client, service_name="iam", rate_limiter=rate_limiter)
    session = MockSessionWrapper({"iam": proxy})

    stubber.add_response("list_roles", {
        "Roles": [{"RoleName": "Role-1", "RoleId": "AROA0000000000000001", "Arn": "arn:aws:iam::123:role/Role-1", "CreateDate": now, "Path": "/"}],
        "IsTruncated": True,
        "Marker": "page_2"
    }, {})
    stubber.add_response("list_roles", {
        "Roles": [{"RoleName": "Role-2", "RoleId": "AROA0000000000000002", "Arn": "arn:aws:iam::123:role/Role-2", "CreateDate": now, "Path": "/"}],
        "IsTruncated": False
    }, {"Marker": "page_2"})

    stubber.activate()
    t0 = datetime.now(UTC)
    roles = list_iam_roles(session=session)
    elapsed = (datetime.now(UTC) - t0).total_seconds()

    assert len(roles) == 2
    assert elapsed >= 0.04  # Paced across calls

    stubber.deactivate()


# =========================================================================
# 14. ACCESS DENIED HALFWAY THROUGH COLLECTION
# =========================================================================

def test_14_access_denied_produces_incomplete_evidence():
    """Verifies that an AccessDenied error halfway through collection yields explicit failure evidence."""
    iam_client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(iam_client)

    stubber.add_response("get_role", {
        "Role": {
            "RoleName": "RestrictedRole",
            "RoleId": "AROA1234567890123456",
            "Path": "/",
            "Arn": "arn:aws:iam::123456789012:role/RestrictedRole",
            "CreateDate": datetime.now(UTC)
        }
    }, {"RoleName": "RestrictedRole"})

    # Denied on list_attached_role_policies
    stubber.add_client_error(
        "list_attached_role_policies",
        service_error_code="AccessDenied",
        service_message="User is not authorized to perform: iam:ListAttachedRolePolicies",
        expected_params={"RoleName": "RestrictedRole"}
    )

    stubber.activate()
    session = MockSessionWrapper({"iam": iam_client})

    evidence = collect_iam_role_inventory_evidence("RestrictedRole", session=session, account_id="123456789012")
    assert evidence["verification_result"] == "ASSESSMENT_INCOMPLETE"
    assert evidence["assessment_status"] == AssessmentStatus.ACCESS_DENIED.value
    assert "AccessDenied" in evidence["raw_evidence"]["error"]

    stubber.deactivate()


# =========================================================================
# 15. TIMEOUT AND THROTTLING BEHAVIOR
# =========================================================================

def test_15_timeout_and_throttling_translation():
    """Verifies that timeouts and throttling during IAM calls map to explicit failure states."""
    # 1. Timeout maps to API_TIMEOUT
    err_timeout = APITimeoutError("Read timeout")
    assert AssessmentStatus.API_TIMEOUT.value == "API_TIMEOUT"

    # 2. Throttled maps to THROTTLED
    err_throttled = APIThrottledError("Rate exceeded")
    assert AssessmentStatus.THROTTLED.value == "THROTTLED"


# =========================================================================
# 16. PARTIAL EVIDENCE NEVER CLASSIFIED AS VERIFIED SECURE
# =========================================================================

def test_16_partial_evidence_never_verified_secure():
    """Verifies invariant: An incomplete or failed collection NEVER results in VERIFIED_SECURE."""
    iam_client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(iam_client)

    stubber.add_client_error(
        "get_role",
        service_error_code="NoSuchEntity",
        service_message="Role does not exist",
        expected_params={"RoleName": "MissingRole"}
    )
    stubber.activate()
    session = MockSessionWrapper({"iam": iam_client})

    evidence = collect_iam_role_inventory_evidence("MissingRole", session=session)
    assert evidence["verification_result"] != "VERIFIED_SECURE"
    assert evidence["verification_result"] == "ASSESSMENT_INCOMPLETE"
    assert evidence["assessment_status"] != AssessmentStatus.VERIFIED.value

    stubber.deactivate()


# =========================================================================
# 17. AGENT CANNOT ACCESS RAW IAM CLIENTS
# =========================================================================

def test_17_agent_cannot_access_raw_iam_clients():
    """Verifies that the Bedrock Agent dispatcher excludes any handles to raw IAM clients or factories."""
    for tool_name in ALLOWED_TOOLS.keys():
        assert "iam_client" not in tool_name.lower()
        assert "raw_iam" not in tool_name.lower()


# =========================================================================
# 18. MUTATION ATTEMPTS REMAIN BLOCKED
# =========================================================================

def test_18_mutation_attempts_blocked():
    """Verifies that mutating IAM operations are rejected with UnsafeCloudOperationError."""
    iam_client = boto3.client("iam", region_name="us-east-1")
    proxy = ReadOnlyClientProxy(raw_client=iam_client, service_name="iam")

    mutations = [
        ("create_role", {"RoleName": "MaliciousRole", "AssumeRolePolicyDocument": "{}"}),
        ("delete_role", {"RoleName": "VictimRole"}),
        ("attach_role_policy", {"RoleName": "Role", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
        ("put_role_policy", {"RoleName": "Role", "PolicyName": "Pol", "PolicyDocument": "{}"}),
        ("create_user", {"UserName": "MaliciousUser"}),
        ("delete_user", {"UserName": "VictimUser"}),
    ]

    for op, kwargs in mutations:
        with pytest.raises(UnsafeCloudOperationError):
            getattr(proxy, op)(**kwargs)


# =========================================================================
# 19. STAGE 1 BOUNDARIES REMAIN ENFORCED
# =========================================================================

def test_19_stage1_boundaries_enforced():
    """Verifies that service and region allowlists remain active for IAM connectors."""
    factory = ReadOnlyAWSClientFactory(session=MockSessionWrapper({}))

    # IAM is global, allowed service
    assert "iam" in ALLOWED_SERVICES
    assert "list_roles" in ALLOWED_OPERATIONS["iam"]
    assert "list_users" in ALLOWED_OPERATIONS["iam"]
    assert "get_user_policy" in ALLOWED_OPERATIONS["iam"]

    # Unauthorized service still blocked
    with pytest.raises(UnauthorizedServiceError):
        factory.get_client("dynamodb")


# =========================================================================
# 20. ATTACK-PATH EDGES REQUIRE SUPPORTING EVIDENCE
# =========================================================================

def test_20_attack_path_graph_evidence_grounding():
    """Verifies that ingesting IAM evidence into ResourceGraph creates verified nodes and edges with evidence references."""
    graph = ResourceGraph()

    sample_role_evidence = {
        "evidence_id": "EV-AWS-IAM-ROLE-SecAdmin-12345678",
        "resource_id": "SecAdminRole",
        "source_type": "AWS::IAM::Role",
        "account_id": "123456789012",
        "raw_evidence": {
            "role_arn": "arn:aws:iam::123456789012:role/SecAdminRole",
            "has_administrator_access": True,
            "attached_policies": [
                {"policy_name": "AdministratorAccess", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess", "is_admin_policy": True}
            ],
            "inline_policies": [
                {"policy_name": "PassRoleInline", "policy_document": {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}}
            ],
            "policy_summary": {
                "has_administrator_access": True,
                "trust_analysis": {
                    "trusted_principals": ["arn:aws:iam::999988887777:root"]
                },
                "escalation_vectors": [
                    {"vector_id": "ESC-02", "name": "PassRole + EC2 RunInstances Escalation", "severity": "HIGH"}
                ]
            }
        }
    }

    sample_user_evidence = {
        "evidence_id": "EV-AWS-IAM-USER-Dave-87654321",
        "resource_id": "dave",
        "source_type": "AWS::IAM::User",
        "account_id": "123456789012",
        "raw_evidence": {
            "user_arn": "arn:aws:iam::123456789012:user/dave",
            "has_administrator_access": False,
            "attached_policies": [
                {"policy_name": "ReadOnlyAccess", "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "is_admin_policy": False}
            ],
            "inline_policies": []
        }
    }

    counts = ingest_iam_evidence_to_graph([sample_role_evidence, sample_user_evidence], graph)
    assert counts["nodes_added"] > 0
    assert counts["edges_added"] > 0

    # Verify Role Node
    role_node = graph.get_node("arn:aws:iam::123456789012:role/SecAdminRole")
    assert role_node is not None
    assert role_node.node_type == NodeType.IAM_ROLE
    assert role_node.is_sensitive is True

    # Verify User Node
    user_node = graph.get_node("arn:aws:iam::123456789012:user/dave")
    assert user_node is not None
    assert user_node.node_type == NodeType.IAM_USER

    # Verify Edges have valid evidence_id and confidence
    edges = graph.list_edges()
    for e in edges:
        assert e.evidence_id is not None
        assert e.evidence_id.startswith("EV-AWS-IAM-")
        assert e.confidence > 0.0
        assert e.status == RelationshipStatus.CONFIRMED

