"""
ExposureFence — Contextual Risk Engine Test Suite
Tests versioned policies (V1, V2), explainable sub-score breakdowns, evidence integrity modifiers,
freshness decay, risk acceptance lifecycle, expiration, and revocation.
"""

from datetime import datetime, timedelta, timezone
import pytest

from backend.graph.attack_paths import AttackPathEngine
from backend.graph.engine import ResourceGraph
from backend.intelligence.models import AssetRecord, CanonicalFinding, FindingSeverity, FindingSource, FindingStatus
from backend.risk.acceptance import RiskAcceptanceService
from backend.risk.engine import ContextualRiskEngine
from backend.risk.policies import RiskPolicyV1, RiskPolicyV2


def test_risk_policy_v1_legacy():
    score, sev, breakdown = RiskPolicyV1.evaluate("S3_PUBLIC")
    assert score == 90.0
    assert sev == FindingSeverity.CRITICAL

    score2, sev2, breakdown2 = RiskPolicyV1.evaluate("SSH_PUBLIC")
    assert score2 == 80.0
    assert sev2 == FindingSeverity.HIGH


def test_risk_policy_v2_multi_factor():
    score, sev, breakdown = RiskPolicyV2.evaluate(
        criticality=100.0,
        exposure=100.0,
        reachability=90.0,
        iam_privilege=80.0,
        blast_radius=70.0,
        integrity_status="VERIFIED",
        freshness_status="FRESH"
    )
    assert score >= 85.0
    assert sev == FindingSeverity.CRITICAL
    assert "asset_criticality_contribution" in breakdown
    assert "internet_exposure_contribution" in breakdown
    assert breakdown["integrity_multiplier"] == 1.0


def test_tampered_evidence_drops_trust():
    score, sev, breakdown = RiskPolicyV2.evaluate(
        criticality=100.0,
        exposure=100.0,
        integrity_status="INTEGRITY_MISMATCH"
    )
    # Score drops to 0 because untrusted/tampered evidence cannot support a risk claim
    assert score == 0.0
    assert breakdown["integrity_multiplier"] == 0.0


def test_stale_evidence_decays_score():
    fresh_score, _, _ = RiskPolicyV2.evaluate(
        criticality=80.0,
        exposure=80.0,
        freshness_status="FRESH"
    )
    stale_score, _, breakdown = RiskPolicyV2.evaluate(
        criticality=80.0,
        exposure=80.0,
        freshness_status="STALE"
    )
    assert stale_score < fresh_score
    assert breakdown["freshness_multiplier"] == 0.7


def test_risk_acceptance_lifecycle(tmp_path):
    db_file = str(tmp_path / "test_risk.db")
    service = RiskAcceptanceService(db_path=db_file)

    # Rejection on short justification
    with pytest.raises(ValueError):
        service.create_acceptance("F-01", "arn:aws:s3:::b1", "Too short", "admin", "2030-01-01T00:00:00Z")

    # Rejection on past expiry
    with pytest.raises(ValueError):
        service.create_acceptance("F-01", "arn:aws:s3:::b1", "Valid justification for audit", "admin", "2020-01-01T00:00:00Z")

    # Valid acceptance
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    acc = service.create_acceptance(
        finding_id="F-S3-001",
        resource_arn="arn:aws:s3:::corp-finance-public-export",
        justification="Executive risk acceptance during migration window",
        approver="ciso-officer",
        expires_at=future
    )
    assert acc.status == "ACTIVE"

    # Active acceptance lookup
    active = service.get_active_acceptance(finding_id="F-S3-001")
    assert active is not None
    assert active.acceptance_id == acc.acceptance_id

    # Revocation
    revoked = service.revoke_acceptance(acc.acceptance_id, revoker="ciso-officer")
    assert revoked is True
    assert service.get_active_acceptance(finding_id="F-S3-001") is None


def test_contextual_risk_engine_integration(tmp_path):
    db_file = str(tmp_path / "test_risk_engine.db")
    engine = ContextualRiskEngine(db_path=db_file)

    finding = CanonicalFinding(
        finding_id="F-SG-001",
        source_id="sg-0123456789abcdef0",
        source_type=FindingSource.NATIVE_EC2,
        raw_finding_hash="hash1",
        resource_arn="arn:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789abcdef0",
        account_id="123456789012",
        region="us-east-1",
        service="ec2",
        resource_type="AWS::EC2::SecurityGroup",
        title="Security Group allows unrestricted ingress on SSH",
        description="Port 22 open to 0.0.0.0/0",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.ACTIVE
    )

    # Without graph context
    base_res = engine.calculate_risk(finding)
    assert base_res.overall_score > 0

    # With graph attack paths
    graph = ResourceGraph.build_default_topology()
    path_engine = AttackPathEngine(graph)
    paths = path_engine.find_all_attack_paths()

    context_res = engine.calculate_risk(finding, attack_paths=paths)
    assert context_res.overall_score >= base_res.overall_score
    assert context_res.is_accepted is False
    assert context_res.effective_score == context_res.overall_score

    # Now create risk acceptance and verify effective score zeroes out
    future = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    engine.acceptance_service.create_acceptance(
        finding_id="F-SG-001",
        resource_arn=finding.resource_arn,
        justification="Temporary firewall exemption for migration",
        approver="head-of-secops",
        expires_at=future
    )

    accepted_res = engine.calculate_risk(finding, attack_paths=paths)
    assert accepted_res.is_accepted is True
    assert accepted_res.overall_score > 0  # Raw score preserved
    assert accepted_res.effective_score == 0.0  # Effective score is 0 due to acceptance
