"""
ExposureFence — RBAC, Compliance & Observability Test Suite
Tests role permissions matrix, compliance framework evaluation (CIS, NIST, MITRE, OWASP),
system health probes, metrics collector, and backup/restore integrity verification.
"""

import os
import pytest

from backend.compliance.service import ComplianceService
from backend.intelligence.models import CanonicalFinding, FindingSeverity, FindingSource, FindingStatus
from backend.observability.backup import create_backup, verify_backup
from backend.observability.health import check_system_health
from backend.observability.metrics import collect_system_metrics
from backend.rbac.models import RBACService, Role


def test_rbac_permissions():
    # Investigator
    assert RBACService.has_permission("INVESTIGATOR", "read:findings") is True
    assert RBACService.has_permission("INVESTIGATOR", "create:proposal") is True
    assert RBACService.has_permission("INVESTIGATOR", "approve:proposal") is False  # Cannot approve

    # Approver
    assert RBACService.has_permission("APPROVER", "approve:proposal") is True
    assert RBACService.has_permission("APPROVER", "execute:remediation") is False

    # Auditor
    assert RBACService.has_permission("AUDITOR", "read:audit") is True
    assert RBACService.has_permission("AUDITOR", "read:dossier") is True
    assert RBACService.has_permission("AUDITOR", "invoke:agent") is False  # Read-only

    # Administrator
    assert RBACService.has_permission("ADMINISTRATOR", "admin:system") is True
    assert RBACService.has_permission("ADMINISTRATOR", "execute:remediation") is True

    # Invalid role
    assert RBACService.has_permission("UNKNOWN_ROLE", "read:findings") is False


def test_compliance_framework_evaluation():
    # Pass sample findings
    findings = [
        CanonicalFinding(
            finding_id="F-S3-01",
            source_id="s3-1",
            source_type=FindingSource.NATIVE_S3,
            raw_finding_hash="h1",
            resource_arn="arn:aws:s3:::corp-finance-public-export",
            account_id="123456789012",
            region="us-east-1",
            service="s3",
            resource_type="AWS::S3::Bucket",
            title="S3 Public Access Enabled",
            description="Public read grants",
            severity=FindingSeverity.CRITICAL,
            status=FindingStatus.ACTIVE,
            compliance_tags=["CIS-2.1.5", "NIST-PR.DS-1", "MITRE-T1530"]
        )
    ]

    report = ComplianceService.evaluate_compliance(findings=findings)
    assert "CIS-AWS-v3.0" in report
    assert "NIST-CSF-2.0" in report
    assert "MITRE-ATTACK" in report
    assert "OWASP-LLM-2025" in report

    # CIS 2.1.5 should be marked FAILED because of active S3 finding
    cis_controls = report["CIS-AWS-v3.0"]["controls"]
    s3_ctrl = next(c for c in cis_controls if c["control_id"] == "CIS-2.1.5")
    assert s3_ctrl["status"] == "FAILED"


def test_system_health_probe():
    health = check_system_health()
    assert health["status"] in ("healthy", "degraded")
    assert "probes" in health
    assert "database_connected" in health["probes"]
    assert "audit_hash_chain_valid" in health["probes"]


def test_system_metrics_collector():
    metrics = collect_system_metrics()
    assert "security_metrics" in metrics
    assert "proposals_pending_review" in metrics["security_metrics"]
    assert "audit_events_logged" in metrics["security_metrics"]
    assert metrics["security_metrics"]["zero_mutation_invariant"] is True


def test_backup_and_restore_verification(tmp_path):
    # Create dummy database and audit log
    db_file = str(tmp_path / "test_backup.db")
    with open(db_file, "w") as f:
        f.write("DUMMY_DB_DATA")

    audit_file = str(tmp_path / "test_audit.jsonl")
    with open(audit_file, "w") as f:
        f.write('{"event": "test"}\n')

    backup_dir = str(tmp_path / "backups")
    res = create_backup(backup_dir=backup_dir, db_path=db_file, audit_path=audit_file)
    manifest_path = res["manifest_path"]
    assert os.path.exists(manifest_path)

    # Verify backup
    assert verify_backup(manifest_path) is True

    # Tamper with backup file
    db_backup_path = os.path.join(backup_dir, res["manifest"]["database_file"])
    with open(db_backup_path, "a") as f:
        f.write("TAMPERED_BYTES")

    # Tampering should be detected
    assert verify_backup(manifest_path) is False
