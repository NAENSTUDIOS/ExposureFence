"""
Tests for Phase 3 Read-Only AWS Connectors
Validates S3, EC2, IAM connectors, data mode switching, normalized evidence generation,
and enforces that connectors contain strictly zero mutation methods.
All tests run offline using Botocore Stubber or mock sessions with zero cloud calls.
"""

from datetime import datetime, UTC
import inspect
import json
import os
import pytest
import boto3
from botocore.stub import Stubber
from botocore.exceptions import ClientError

from backend.connectors import (
    get_data_mode,
    is_aws_mode_enabled,
    get_boto3_session,
    list_s3_buckets,
    get_bucket_public_access_block,
    get_bucket_policy_status,
    get_bucket_acl,
    get_bucket_policy,
    collect_s3_exposure_evidence,
    describe_security_groups,
    analyze_security_group_ingress,
    collect_ec2_exposure_evidence,
    list_iam_roles,
    get_role_details,
    list_attached_role_policies,
    collect_iam_exposure_evidence,
)
import backend.connectors.aws_s3 as s3_mod
import backend.connectors.aws_ec2 as ec2_mod
import backend.connectors.aws_iam as iam_mod


def test_data_mode_configuration():
    """Validates EXPOSUREFENCE_DATA_MODE resolution and defaults."""
    # Default is mock
    if "EXPOSUREFENCE_DATA_MODE" in os.environ:
        del os.environ["EXPOSUREFENCE_DATA_MODE"]
    assert get_data_mode() == "mock"
    assert is_aws_mode_enabled() is False

    # Explicit aws
    os.environ["EXPOSUREFENCE_DATA_MODE"] = "aws"
    try:
        assert get_data_mode() == "aws"
        assert is_aws_mode_enabled() is True
    finally:
        del os.environ["EXPOSUREFENCE_DATA_MODE"]

    # Unknown mode falls back to mock
    os.environ["EXPOSUREFENCE_DATA_MODE"] = "something_invalid"
    try:
        assert get_data_mode() == "mock"
        assert is_aws_mode_enabled() is False
    finally:
        del os.environ["EXPOSUREFENCE_DATA_MODE"]


def test_zero_mutation_invariant_on_connectors():
    """Enforces that connectors contain only read-only inspect/collect methods."""
    forbidden_prefixes = (
        "put_", "delete_", "create_", "update_", "modify_",
        "authorize_", "revoke_", "attach_", "detach_", "post_", "remove_"
    )
    for mod in [s3_mod, ec2_mod, iam_mod]:
        for name, fn in inspect.getmembers(mod, inspect.isfunction):
            for prefix in forbidden_prefixes:
                assert not name.startswith(prefix), f"Connector {mod.__name__} violates read-only invariant with function: {name}"


class MockSession:
    """Mock Boto3 session wrapper to supply stubbed clients."""
    def __init__(self, clients):
        self._clients = clients

    def client(self, service_name, **kwargs):
        if service_name in self._clients:
            return self._clients[service_name]
        raise ValueError(f"No mock client for service {service_name}")


def test_s3_connector_stubbed():
    """Tests S3 connector read operations and public block detection via botocore Stubber."""
    s3_client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3_client)
    mock_session = MockSession({"s3": s3_client})

    # 1. list_buckets
    now = datetime.now(UTC)
    stubber.add_response("list_buckets", {
        "Buckets": [
            {"Name": "test-bucket-alpha", "CreationDate": now},
            {"Name": "test-bucket-beta", "CreationDate": now}
        ]
    })

    # 2. get_public_access_block (Alpha: effective)
    stubber.add_response("get_public_access_block", {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }
    }, {"Bucket": "test-bucket-alpha"})

    # 3. get_bucket_policy_status (Alpha: not public)
    stubber.add_response("get_bucket_policy_status", {
        "PolicyStatus": {"IsPublic": False}
    }, {"Bucket": "test-bucket-alpha"})

    # 4. get_bucket_acl (Alpha: private)
    stubber.add_response("get_bucket_acl", {
        "Grants": [
            {
                "Grantee": {"Type": "CanonicalUser", "DisplayName": "owner"},
                "Permission": "FULL_CONTROL"
            }
        ]
    }, {"Bucket": "test-bucket-alpha"})

    stubber.activate()

    buckets = list_s3_buckets(session=mock_session)
    assert len(buckets) == 2
    assert buckets[0]["name"] == "test-bucket-alpha"

    pab = get_bucket_public_access_block("test-bucket-alpha", session=mock_session)
    assert pab["is_effective"] is True

    policy_status = get_bucket_policy_status("test-bucket-alpha", session=mock_session)
    assert policy_status["is_public"] is False

    acl = get_bucket_acl("test-bucket-alpha", session=mock_session)
    assert acl["is_public_acl"] is False

    stubber.deactivate()


def test_s3_connector_not_found_handling():
    """Tests that missing PAB or bucket policy handles NoSuch* errors gracefully."""
    s3_client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3_client)
    mock_session = MockSession({"s3": s3_client})

    stubber.add_client_error(
        "get_public_access_block",
        service_error_code="NoSuchPublicAccessBlockConfiguration",
        service_message="The public access block configuration was not found",
        expected_params={"Bucket": "unconfigured-bucket"}
    )
    stubber.add_client_error(
        "get_bucket_policy_status",
        service_error_code="NoSuchBucketPolicy",
        service_message="The bucket policy does not exist",
        expected_params={"Bucket": "unconfigured-bucket"}
    )
    stubber.add_client_error(
        "get_bucket_policy",
        service_error_code="NoSuchBucketPolicy",
        service_message="The bucket policy does not exist",
        expected_params={"Bucket": "unconfigured-bucket"}
    )

    stubber.activate()

    pab = get_bucket_public_access_block("unconfigured-bucket", session=mock_session)
    assert pab["is_effective"] is False

    pol_status = get_bucket_policy_status("unconfigured-bucket", session=mock_session)
    assert pol_status["is_public"] is False

    pol = get_bucket_policy("unconfigured-bucket", session=mock_session)
    assert pol is None

    stubber.deactivate()


def test_s3_evidence_generation():
    """Tests normalized evidence dictionary formatting for S3."""
    s3_client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3_client)
    mock_session = MockSession({"s3": s3_client})

    # Public bucket: PAB missing, Policy is public
    stubber.add_client_error(
        "get_public_access_block",
        service_error_code="NoSuchPublicAccessBlockConfiguration",
        expected_params={"Bucket": "exposed-bucket"}
    )
    stubber.add_response(
        "get_bucket_policy_status",
        {"PolicyStatus": {"IsPublic": True}},
        {"Bucket": "exposed-bucket"}
    )
    stubber.add_response(
        "get_bucket_acl",
        {
            "Grants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                    },
                    "Permission": "READ"
                }
            ]
        },
        {"Bucket": "exposed-bucket"}
    )

    stubber.activate()
    evidence = collect_s3_exposure_evidence("exposed-bucket", session=mock_session, account_id="123456789012")
    stubber.deactivate()

    assert evidence["source_type"] == "AWS::S3::Bucket"
    assert evidence["resource_id"] == "exposed-bucket"
    assert evidence["account_id"] == "123456789012"
    assert evidence["verification_result"] == "EXPOSURE_DETECTED"
    assert "sha256" in evidence
    assert len(evidence["sha256"]) == 64
    assert evidence["evidence_id"].startswith("EV-AWS-S3-exposed-bucket-")


def test_ec2_security_group_connector():
    """Tests EC2 connector ingress analysis and evidence generation."""
    sg_exposed = {
        "GroupId": "sg-0123456789abcdef0",
        "GroupName": "open-ssh-rdp",
        "VpcId": "vpc-001",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
            }
        ]
    }

    findings = analyze_security_group_ingress(sg_exposed)
    assert len(findings) == 2
    assert findings[0]["is_ssh_exposed"] is True
    assert findings[1]["is_rdp_exposed"] is True

    evidence = collect_ec2_exposure_evidence(sg_exposed, account_id="123456789012")
    assert evidence["source_type"] == "AWS::EC2::SecurityGroup"
    assert evidence["verification_result"] == "EXPOSURE_DETECTED"
    assert evidence["evidence_id"].startswith("EV-AWS-SG-sg-0123456789abcdef0-")
    assert len(evidence["sha256"]) == 64


def test_iam_connector():
    """Tests IAM connector role and policy analysis."""
    iam_client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(iam_client)
    mock_session = MockSession({"iam": iam_client})

    now = datetime.now(UTC)
    role_name = "SuperAdminRole"

    stubber.add_response("get_role", {
        "Role": {
            "Path": "/",
            "RoleName": role_name,
            "RoleId": "AROA1234567890EXAMPLE",
            "Arn": f"arn:aws:iam::123456789012:role/{role_name}",
            "CreateDate": now,
            "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17"})
        }
    }, {"RoleName": role_name})

    stubber.add_response("list_attached_role_policies", {
        "AttachedPolicies": [
            {
                "PolicyName": "AdministratorAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            }
        ]
    }, {"RoleName": role_name})

    stubber.activate()
    evidence = collect_iam_exposure_evidence(role_name, session=mock_session, account_id="123456789012")
    stubber.deactivate()

    assert evidence["source_type"] == "AWS::IAM::Role"
    assert evidence["resource_id"] == role_name
    assert evidence["verification_result"] == "PRIVILEGED_ACCESS"
    assert evidence["raw_evidence"]["has_administrator_access"] is True
    assert evidence["evidence_id"].startswith("EV-AWS-IAM-SuperAdminRole-")
    assert len(evidence["sha256"]) == 64
