"""
ExposureFence — Multi-Source Intelligence Test Suite
Tests canonical models, normalization, adapters (S3, EC2, IAM, SecurityHub, Config, Prowler),
correlation, lifecycle transitions, asset inventory, and configuration drift detection.
"""

from datetime import datetime, timedelta, timezone
import os
import pytest

from backend.intelligence.config_adapter import AWSConfigAdapter
from backend.intelligence.correlation import CorrelationEngine
from backend.intelligence.ec2_adapter import EC2Adapter
from backend.intelligence.iam_adapter import IAMAdapter
from backend.intelligence.inventory import AssetInventoryRepository
from backend.intelligence.lifecycle import FindingLifecycleManager
from backend.intelligence.models import (
    AssetRecord,
    CanonicalFinding,
    FindingSeverity,
    FindingSource,
    FindingStatus,
)
from backend.intelligence.normalization import (
    compute_raw_hash,
    normalize_arn,
    normalize_severity,
    normalize_timestamp,
    sanitize_untrusted_text,
)
from backend.intelligence.prowler_adapter import ProwlerAdapter
from backend.intelligence.s3_adapter import S3Adapter
from backend.intelligence.securityhub_adapter import SecurityHubAdapter
from backend.intelligence.service import MultiSourceIntelligenceService


def test_severity_normalization():
    assert normalize_severity("CRITICAL") == FindingSeverity.CRITICAL
    assert normalize_severity("HIGH") == FindingSeverity.HIGH
    assert normalize_severity("medium") == FindingSeverity.MEDIUM
    assert normalize_severity("low") == FindingSeverity.LOW
    assert normalize_severity("INFORMATIONAL") == FindingSeverity.INFORMATIONAL
    # Numeric values
    assert normalize_severity(95) == FindingSeverity.CRITICAL
    assert normalize_severity(75) == FindingSeverity.HIGH
    assert normalize_severity(45) == FindingSeverity.MEDIUM
    assert normalize_severity(10) == FindingSeverity.LOW
    assert normalize_severity(0) == FindingSeverity.INFORMATIONAL
    assert normalize_severity(None) == FindingSeverity.INFORMATIONAL


def test_arn_normalization():
    assert normalize_arn("my-bucket", "s3") == "arn:aws:s3:::my-bucket"
    assert normalize_arn("arn:aws:s3:::already-arn", "s3") == "arn:aws:s3:::already-arn"
    assert normalize_arn("sg-12345678", "ec2", region="us-east-1") == "arn:aws:ec2:us-east-1:123456789012:security-group/sg-12345678"
    assert normalize_arn("MyRole", "iam") == "arn:aws:iam::123456789012:role/MyRole"


def test_sanitize_untrusted_text():
    evil = "Safe text\x00\x08with control characters"
    assert sanitize_untrusted_text(evil) == "Safe textwith control characters"
    long_text = "A" * 3000
    sanitized = sanitize_untrusted_text(long_text, max_len=100)
    assert len(sanitized) > 100
    assert "... [TRUNCATED]" in sanitized


def test_s3_adapter_from_fixture():
    findings = S3Adapter.load_from_fixture()
    assert len(findings) >= 1
    f = findings[0]
    assert f.source_type == FindingSource.NATIVE_S3
    assert f.severity == FindingSeverity.CRITICAL
    assert "s3" in f.resource_arn


def test_ec2_adapter_from_fixture():
    findings = EC2Adapter.load_from_fixture()
    assert len(findings) >= 1
    f = findings[0]
    assert f.source_type == FindingSource.NATIVE_EC2
    assert f.severity == FindingSeverity.HIGH
    assert "sg-" in f.resource_arn


def test_iam_adapter():
    rec = {
        "resource_id": "TestAdminRole",
        "has_administrator_access": True,
        "attached_policies": [{"policy_name": "AdministratorAccess", "is_admin_policy": True}]
    }
    finding = IAMAdapter.from_record(rec)
    assert finding is not None
    assert finding.source_type == FindingSource.NATIVE_IAM
    assert finding.severity == FindingSeverity.HIGH
    assert "TestAdminRole" in finding.resource_arn


def test_securityhub_adapter_from_fixture():
    findings = SecurityHubAdapter.load_from_fixture()
    assert len(findings) == 2
    for f in findings:
        assert f.source_type == FindingSource.SECURITY_HUB
        assert f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
        assert f.raw_finding_hash is not None


def test_config_adapter_from_fixture():
    findings = AWSConfigAdapter.load_from_fixture()
    assert len(findings) == 2
    for f in findings:
        assert f.source_type == FindingSource.AWS_CONFIG
        assert f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)


def test_prowler_adapter_from_fixture():
    findings = ProwlerAdapter.load_from_fixture()
    assert len(findings) == 2
    for f in findings:
        assert f.source_type == FindingSource.PROWLER
        assert len(f.compliance_tags) > 0


def test_correlation_and_deduplication():
    sh_findings = SecurityHubAdapter.load_from_fixture()
    prowler_findings = ProwlerAdapter.load_from_fixture()
    combined = sh_findings + prowler_findings

    correlated = CorrelationEngine.correlate_findings(combined)
    assert len(correlated) == 4

    groups = CorrelationEngine.group_by_correlation(correlated)
    # The S3 bucket should have findings from both Security Hub and Prowler under the same correlation_id
    s3_arn = "arn:aws:s3:::corp-finance-public-export"
    s3_findings = [f for f in correlated if f.resource_arn == s3_arn]
    assert len(s3_findings) == 2
    assert s3_findings[0].correlation_id == s3_findings[1].correlation_id


def test_finding_lifecycle_and_suppression():
    findings = S3Adapter.load_from_fixture()
    fnd = findings[0]
    assert fnd.status == FindingStatus.ACTIVE

    # Test invalid suppression (empty justification)
    with pytest.raises(ValueError):
        FindingLifecycleManager.suppress(fnd, "", "2030-01-01T00:00:00Z")

    # Test invalid suppression (past expiry)
    with pytest.raises(ValueError):
        FindingLifecycleManager.suppress(fnd, "Valid reason", "2020-01-01T00:00:00Z")

    # Valid suppression
    future = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    fnd = FindingLifecycleManager.suppress(fnd, "Approved temporary maintenance", future, approver="secops-lead")
    assert fnd.status == FindingStatus.SUPPRESSED
    assert "[secops-lead]" in fnd.suppression_reason

    # Test resolve and reopen
    fnd = FindingLifecycleManager.resolve(fnd)
    assert fnd.status == FindingStatus.RESOLVED
    fnd = FindingLifecycleManager.reopen(fnd)
    assert fnd.status == FindingStatus.REOPENED


def test_asset_inventory_and_drift_detection(tmp_path):
    db_file = str(tmp_path / "test_inventory.db")
    repo = AssetInventoryRepository(db_path=db_file)

    asset1 = AssetRecord(
        resource_arn="arn:aws:s3:::audit-bucket",
        account_id="123456789012",
        region="us-east-1",
        service="s3",
        resource_type="AWS::S3::Bucket",
        resource_id="audit-bucket",
        configuration_digest="hash_v1",
        tags={"Env": "Prod"}
    )
    repo.register_asset(asset1)

    fetched = repo.get_asset("arn:aws:s3:::audit-bucket")
    assert fetched is not None
    assert fetched.drift_detected is False

    # Simulate unapproved configuration drift
    asset1_modified = AssetRecord(
        resource_arn="arn:aws:s3:::audit-bucket",
        account_id="123456789012",
        region="us-east-1",
        service="s3",
        resource_type="AWS::S3::Bucket",
        resource_id="audit-bucket",
        configuration_digest="hash_v2_unapproved_change",
        tags={"Env": "Prod"}
    )
    repo.register_asset(asset1_modified)

    fetched2 = repo.get_asset("arn:aws:s3:::audit-bucket")
    assert fetched2 is not None
    assert fetched2.drift_detected is True


def test_multi_source_intelligence_service(tmp_path):
    db_file = str(tmp_path / "test_intel.db")
    svc = MultiSourceIntelligenceService(db_path=db_file)

    findings = svc.ingest_all_sources()
    assert len(findings) >= 5

    # Test query APIs
    criticals = svc.list_findings(severity="CRITICAL")
    assert len(criticals) >= 1

    s3_findings = svc.list_findings(service="s3")
    assert len(s3_findings) >= 2

    # Test suppression via service
    target_id = findings[0].finding_id
    future_exp = (datetime.now(timezone.utc) + timedelta(days=14)).isoformat()
    suppressed = svc.suppress_finding(target_id, "Waiver granted for pen-testing", future_exp)
    assert suppressed is not None
    assert suppressed.status == FindingStatus.SUPPRESSED

    # Re-fetch from DB
    persisted = svc.get_finding(target_id)
    assert persisted.status == FindingStatus.SUPPRESSED
