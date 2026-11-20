"""
Tests for Evidence Engine End-to-End Integration
Validates ingestion of mock fixtures, adaptation of read-only AWS connector outputs,
backward compatibility with scoring.evidence, and zero cloud API invocations.
"""

from datetime import datetime, timezone
import boto3
from botocore.stub import Stubber
import pytest

from backend.evidence.collector import (
    collect_from_aws_ec2,
    collect_from_aws_iam,
    collect_from_aws_s3,
    collect_from_mock_s3,
    collect_from_mock_security_groups,
)
from backend.evidence.models import SourceMode
from backend.evidence.repository import EvidenceRepository
from backend.evidence.service import EvidenceService
from scoring.evidence import evidence_exists, get_evidence


class MockSession:
    def __init__(self, clients):
        self._clients = clients

    def client(self, name, **kwargs):
        if name in self._clients:
            return self._clients[name]
        raise ValueError(f"No mock client for {name}")


@pytest.fixture
def temp_service(tmp_path):
    db_file = str(tmp_path / "integration_evidence.db")
    return EvidenceService(db_path=db_file)


def test_mock_fixture_ingestion_end_to_end(temp_service):
    """Ingests mock fixtures into isolated ledger, verifies records and ledger health."""
    ingested = temp_service.ingest_mock_data()
    assert len(ingested) > 0

    health = temp_service.get_ledger_health()
    assert health["total_records"] == len(ingested)
    assert health["chain_valid"] is True
    assert len(health["issues"]) == 0
    assert len(health["latest_record_hash"]) == 64


def test_aws_s3_connector_evidence_adaptation(temp_service):
    """Adapts read-only AWS S3 connector output into unified EvidenceRecord."""
    s3_client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(s3_client)
    mock_session = MockSession({"s3": s3_client})

    # Public Access Block effective
    stubber.add_response("get_public_access_block", {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True
        }
    }, {"Bucket": "corp-analytics-bucket"})

    stubber.add_response("get_bucket_policy_status", {
        "PolicyStatus": {"IsPublic": False}
    }, {"Bucket": "corp-analytics-bucket"})

    stubber.add_response("get_bucket_acl", {
        "Grants": [{"Grantee": {"Type": "CanonicalUser"}, "Permission": "FULL_CONTROL"}]
    }, {"Bucket": "corp-analytics-bucket"})

    stubber.activate()
    rec = collect_from_aws_s3("corp-analytics-bucket", session=mock_session, account_id="123456789012")
    stubber.deactivate()

    stored = temp_service.ingest_record(rec)
    assert stored.source_mode == SourceMode.AWS_READ_ONLY.value
    assert stored.resource_id == "corp-analytics-bucket"
    assert stored.provenance.source_reference.startswith("aws://123456789012/us-east-1/s3/")

    health = temp_service.get_ledger_health()
    assert health["chain_valid"] is True


def test_aws_ec2_connector_evidence_adaptation(temp_service):
    """Adapts read-only AWS EC2 connector output into unified EvidenceRecord."""
    sg_data = {
        "GroupId": "sg-open-web",
        "GroupName": "open-http-https",
        "VpcId": "vpc-001",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    }

    rec = collect_from_aws_ec2(sg_data, account_id="123456789012", region="us-east-1")
    stored = temp_service.ingest_record(rec)

    assert stored.source_mode == SourceMode.AWS_READ_ONLY.value
    assert stored.resource_id == "sg-open-web"
    assert stored.source_type == "AWS::EC2::SecurityGroup"

    health = temp_service.get_ledger_health()
    assert health["chain_valid"] is True


def test_aws_iam_connector_evidence_adaptation(temp_service):
    """Adapts read-only AWS IAM connector output into unified EvidenceRecord."""
    iam_client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(iam_client)
    mock_session = MockSession({"iam": iam_client})

    now = datetime.now(timezone.utc)
    stubber.add_response("get_role", {
        "Role": {
            "Path": "/",
            "RoleName": "AuditInspectorRole",
            "RoleId": "AROA-INSPECTOR-1234",
            "Arn": "arn:aws:iam::123456789012:role/AuditInspectorRole",
            "CreateDate": now
        }
    }, {"RoleName": "AuditInspectorRole"})

    stubber.add_response("list_attached_role_policies", {
        "AttachedPolicies": [
            {"PolicyName": "SecurityAudit", "PolicyArn": "arn:aws:iam::aws:policy/SecurityAudit"}
        ]
    }, {"RoleName": "AuditInspectorRole"})

    stubber.activate()
    rec = collect_from_aws_iam("AuditInspectorRole", session=mock_session, account_id="123456789012")
    stubber.deactivate()

    stored = temp_service.ingest_record(rec)
    assert stored.source_mode == SourceMode.AWS_READ_ONLY.value
    assert stored.resource_id == "AuditInspectorRole"
    assert stored.normalized_evidence["has_administrator_access"] is False

    health = temp_service.get_ledger_health()
    assert health["chain_valid"] is True


def test_backward_compatibility_layer():
    """Validates that legacy evidence registry functions continue to resolve."""
    # Legacy static IDs
    assert evidence_exists("EV-S3-001") is True
    assert evidence_exists("EV-SG-001") is True
    assert evidence_exists("EV-UNKNOWN-999") is False

    desc = get_evidence("EV-S3-001")
    assert desc == "Public S3 bucket evidence"
