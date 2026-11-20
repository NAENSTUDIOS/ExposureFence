"""
ExposureFence — Phase 9 Red-Team Workstream 4: Evidence & Compliance Assurance
Adversarial test cases targeting:
- Evidence payload tampering and RFC 8785 canonical hash mismatch detection
- Stale evidence timestamp manipulation and freshness decay multiplier
- Compliance control isolation (verifying unrelated findings do not fail controls)
- Exact control failure on genuine non-compliance
- Sealed cryptographic evidence dossier tamper detection and Merkle root verification
"""

from collections import namedtuple
from datetime import datetime, timedelta, timezone
import json
import pytest

from backend.compliance.service import ComplianceService
from backend.governance.dossier import EvidenceDossierGenerator
from backend.intelligence.models import (
    AssetRecord,
    CanonicalFinding,
    FindingSeverity,
    FindingSource,
    FindingStatus,
)
from backend.risk.engine import ContextualRiskEngine


MockEvidence = namedtuple("MockEvidence", ["evidence_id", "integrity_status", "freshness_status"])


def test_evidence_tamper_detection_rfc8785_canonical_hash():
    """
    ATTACK: Adversary modifies a whitespace, reorders keys, or alters values in evidence payload.
    DEFENSE: RFC 8785 canonical serialization produces a completely different SHA-256 hash, detecting tampering.
    """
    from backend.evidence.hashing import compute_payload_digest

    payload_original = {
        "bucket_name": "vault-001",
        "BlockPublicAcls": True,
        "is_public_policy": False,
        "tags": {"Environment": "Production", "Owner": "SecOps"}
    }
    hash_original = compute_payload_digest(payload_original)

    # 1. Key reordering (canonical JSON must produce IDENTICAL hash)
    payload_reordered = {
        "tags": {"Owner": "SecOps", "Environment": "Production"},
        "is_public_policy": False,
        "BlockPublicAcls": True,
        "bucket_name": "vault-001"
    }
    hash_reordered = compute_payload_digest(payload_reordered)
    assert hash_original == hash_reordered

    # 2. Tampered value (bit-flip: BlockPublicAcls set to False)
    payload_tampered = dict(payload_original)
    payload_tampered["BlockPublicAcls"] = False
    hash_tampered = compute_payload_digest(payload_tampered)
    assert hash_original != hash_tampered


def test_evidence_stale_evidence_decay_multiplier():
    """
    ATTACK: Adversary supplies 30-day-old evidence claiming a resource was private in the past.
    DEFENSE: Risk engine detects stale evidence (> 24 hours) and applies freshness penalty multiplier.
    """
    risk_engine = ContextualRiskEngine()

    fresh_finding = CanonicalFinding(
        finding_id="FIND-FRESH-001",
        source_id="NATIVE_S3",
        source_type=FindingSource.NATIVE_S3,
        raw_finding_hash="hash001",
        resource_arn="arn:aws:s3:::audit-vault",
        account_id="123456789012",
        region="us-east-1",
        service="s3",
        resource_type="s3_bucket",
        title="Public Read S3 Bucket",
        description="Public access enabled",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.ACTIVE
    )

    asset = AssetRecord(
        resource_arn="arn:aws:s3:::audit-vault",
        account_id="123456789012",
        region="us-east-1",
        service="s3",
        resource_type="s3_bucket",
        resource_id="audit-vault",
        tags={"Environment": "Production"}
    )

    # Fresh evidence (factor = 1.0)
    score_fresh = risk_engine.calculate_risk(
        finding=fresh_finding,
        asset=asset,
        evidence=MockEvidence("EV-01", "VERIFIED", "FRESH")
    )

    # Stale evidence (factor = 0.7)
    score_stale = risk_engine.calculate_risk(
        finding=fresh_finding,
        asset=asset,
        evidence=MockEvidence("EV-01", "VERIFIED", "STALE")
    )

    assert score_fresh.effective_score > score_stale.effective_score
    assert score_stale.component_breakdown["freshness_multiplier"] == 0.70


def test_compliance_fine_grained_control_isolation():
    """
    ATTACK/BUG VERIFICATION (Finding 4):
    An active finding on S3 (e.g. S3 Server-Side Encryption or Lifecycle) must NOT incorrectly fail
    CIS-2.1.5 ('Ensure that S3 Buckets are configured with Block Public Access').
    DEFENSE: Compliance service matches specific control invariants rather than coarse service-level failures.
    """
    # Create an S3 finding completely unrelated to public access (e.g. Bucket Lifecycle Policy)
    unrelated_s3_finding = CanonicalFinding(
        finding_id="FIND-S3-ENCR-001",
        source_id="AWS_CONFIG",
        source_type=FindingSource.AWS_CONFIG,
        raw_finding_hash="hash002",
        resource_arn="arn:aws:s3:::internal-archive",
        account_id="123456789012",
        region="us-east-1",
        service="s3",
        resource_type="s3_bucket",
        title="S3 Bucket Lifecycle Configuration Missing",
        description="Bucket does not have automated lifecycle transition rules configured.",
        severity=FindingSeverity.MEDIUM,
        status=FindingStatus.ACTIVE,
        compliance_tags=["CIS-AWS-3.1"]  # Does not match CIS-2.1.5
    )

    report = ComplianceService.evaluate_compliance(findings=[unrelated_s3_finding])
    cis_controls = report["CIS-AWS-v3.0"]["controls"]

    # Locate CIS-2.1.5 (Block Public Access)
    bpa_ctrl = next(c for c in cis_controls if c["control_id"] == "CIS-2.1.5")

    # MUST REMAIN PASSED! (Unrelated finding does not fail Block Public Access)
    assert bpa_ctrl["status"] == "PASSED"
    assert len(bpa_ctrl["violating_findings"]) == 0


def test_compliance_target_control_exact_failure():
    """
    VERIFICATION:
    An active finding that specifically violates S3 Public Access DOES fail CIS-2.1.5,
    while unrelated IAM controls (CIS-1.16) remain unaffected.
    """
    bpa_violating_finding = CanonicalFinding(
        finding_id="FIND-S3-PUB-001",
        source_id="NATIVE_S3",
        source_type=FindingSource.NATIVE_S3,
        raw_finding_hash="hash003",
        resource_arn="arn:aws:s3:::public-bucket-123",
        account_id="123456789012",
        region="us-east-1",
        service="s3",
        resource_type="s3_bucket",
        title="Public Read Access via Bucket Policy",
        description="Amazon S3 bucket has Block Public Access disabled and public read policy.",
        severity=FindingSeverity.CRITICAL,
        status=FindingStatus.ACTIVE,
        compliance_tags=["CIS-2.1.5", "SEC-S3-001"]
    )

    report = ComplianceService.evaluate_compliance(findings=[bpa_violating_finding])
    cis_controls = report["CIS-AWS-v3.0"]["controls"]

    bpa_ctrl = next(c for c in cis_controls if c["control_id"] == "CIS-2.1.5")
    iam_ctrl = next(c for c in cis_controls if c["control_id"] == "CIS-1.16")

    # S3 BPA control MUST FAIL
    assert bpa_ctrl["status"] == "FAILED"
    assert "FIND-S3-PUB-001" in bpa_ctrl["violating_findings"]

    # IAM control MUST REMAIN PASSED
    assert iam_ctrl["status"] == "PASSED"


def test_dossier_integrity_merkle_root_verification():
    """
    ATTACK: Adversary intercepts a sealed evidence dossier and modifies an approver name or rule outcome.
    DEFENSE: Dossier verification recalculates the SHA-256 Merkle root digest over RFC 8785 canonical JSON;
    any modification invalidates the dossier.
    """
    pkg = EvidenceDossierGenerator.generate_dossier(
        proof_chain_record={
            "chain_id": "CHN-TEST-999",
            "approver_identity": "ciso_officer",
            "approval_timestamp": "2026-11-21T01:00:00Z",
            "lifecycle_state": "VERIFIED"
        },
        finding_details={"finding_id": "F-01", "resource_arn": "arn:aws:s3:::vault-01", "severity": "CRITICAL"},
        evidence_record={"evidence_id": "EV-01", "payload_sha256": "original_payload_hash", "integrity_status": "VERIFIED"},
        rule_evaluation={"rule_id": "SEC-S3-001", "status": "FAIL"},
        risk_score_details={"overall_score": 92.5, "severity": "CRITICAL", "component_breakdown": {}},
        remediation_plan={"action_type": "enable_s3_block_public_access", "plan_digest": "plan_digest_abc"}
    )

    # 1. Clean dossier passes verification
    assert EvidenceDossierGenerator.verify_dossier(pkg) is True

    # 2. Tampered approver identity
    pkg_tampered = json.loads(json.dumps(pkg))
    pkg_tampered["dossier"]["governance"]["approver"] = "forged_malicious_user"
    assert EvidenceDossierGenerator.verify_dossier(pkg_tampered) is False

    # 3. Tampered target severity
    pkg_tampered2 = json.loads(json.dumps(pkg))
    pkg_tampered2["dossier"]["target"]["severity"] = "LOW_TAMPERED"
    assert EvidenceDossierGenerator.verify_dossier(pkg_tampered2) is False
