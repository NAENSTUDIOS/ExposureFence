"""
ExposureFence — Phase 9 Red-Team Workstream 1: Governance Attack Testing
Adversarial test cases targeting:
- Forged approver identity and role spoofing
- Approval bypass attempts (executing unapproved proposals)
- Unauthorized execution role attempts (non-administrators executing)
- Expired approval replay and race condition prevention
- Pre-execution evidence substitution detection
- Session identity validation at trusted boundaries
"""

from datetime import datetime, timedelta, timezone
import pytest

from backend.governance.models import ProposalLifecycleState
from backend.governance.proof_chain import ProofChainService
from backend.governance.state_machine import RemediationStateMachine
from backend.session_store import create_session, destroy_session


def test_governance_forged_approver_role(tmp_path):
    """
    ATTACK: Adversary attempts to approve a proposal using an unauthorized role (INVESTIGATOR, AUDITOR).
    DEFENSE: State machine and ProofChainService strictly enforce that caller_role must be APPROVER or ADMINISTRATOR.
    """
    db_file = str(tmp_path / "test_gov_forged_role.db")
    svc = ProofChainService(db_path=db_file)
    future_exp = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()

    chain = svc.create_investigation_chain(
        finding_id="F-S3-001",
        resource_arn="arn:aws:s3:::sensitive-data",
        evidence_id="EV-S3-001",
        evidence_digest="hash123",
        rule_id="SEC-S3-001",
        rule_version="1.0.0",
        rule_set_digest="rulehash",
        risk_score=90.0,
        risk_policy_version="2.0.0",
        remediation_action="enable_s3_block_public_access",
        parameters={"bucket_name": "sensitive-data"}
    )

    # 1. Attempt approval as INVESTIGATOR
    with pytest.raises(PermissionError) as exc:
        svc.authorize_approval(
            chain_id=chain.chain_id,
            approver="attacker_user",
            caller_role="INVESTIGATOR",
            expires_at=future_exp
        )
    assert "Role 'APPROVER' or 'ADMINISTRATOR' required" in str(exc.value)

    # 2. Attempt approval as AUDITOR
    with pytest.raises(PermissionError) as exc:
        svc.authorize_approval(
            chain_id=chain.chain_id,
            approver="auditor_user",
            caller_role="AUDITOR",
            expires_at=future_exp
        )
    assert "Role 'APPROVER' or 'ADMINISTRATOR' required" in str(exc.value)

    # Chain remains PENDING
    persisted = svc.get_chain(chain.chain_id)
    assert persisted.lifecycle_state == ProposalLifecycleState.PENDING


def test_governance_approval_bypass_direct_execution(tmp_path):
    """
    ATTACK: Adversary bypasses human approval and directly invokes execute_and_verify on a PENDING proposal.
    DEFENSE: Execution strictly requires that the chain must currently be in APPROVED state.
    """
    db_file = str(tmp_path / "test_gov_bypass.db")
    svc = ProofChainService(db_path=db_file)

    chain = svc.create_investigation_chain(
        finding_id="F-S3-001",
        resource_arn="arn:aws:s3:::sensitive-data",
        evidence_id="EV-S3-001",
        evidence_digest="hash123",
        rule_id="SEC-S3-001",
        rule_version="1.0.0",
        rule_set_digest="rulehash",
        risk_score=90.0,
        risk_policy_version="2.0.0",
        remediation_action="enable_s3_block_public_access",
        parameters={"bucket_name": "sensitive-data"}
    )

    # Attempt direct execution while still in PENDING state
    with pytest.raises(PermissionError) as exc:
        svc.execute_and_verify(
            chain_id=chain.chain_id,
            current_evidence_digest="hash123",
            caller_role="ADMINISTRATOR"
        )
    assert "Proposal must be in 'APPROVED' state" in str(exc.value)


def test_governance_unauthorized_execution_role(tmp_path):
    """
    ATTACK: Approver or Investigator attempts to execute remediation.
    DEFENSE: Execution strictly enforces that caller_role must possess 'ADMINISTRATOR' privileges.
    """
    db_file = str(tmp_path / "test_gov_unauth_exec.db")
    svc = ProofChainService(db_path=db_file)
    future_exp = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()

    chain = svc.create_investigation_chain(
        finding_id="F-S3-001",
        resource_arn="arn:aws:s3:::sensitive-data",
        evidence_id="EV-S3-001",
        evidence_digest="hash123",
        rule_id="SEC-S3-001",
        rule_version="1.0.0",
        rule_set_digest="rulehash",
        risk_score=90.0,
        risk_policy_version="2.0.0",
        remediation_action="enable_s3_block_public_access",
        parameters={"bucket_name": "sensitive-data"}
    )

    # Legitimate approval
    svc.authorize_approval(
        chain_id=chain.chain_id,
        approver="legit_approver",
        caller_role="APPROVER",
        expires_at=future_exp
    )

    # Approver tries to execute their own proposal (Separation of Duties violation)
    with pytest.raises(PermissionError) as exc:
        svc.execute_and_verify(
            chain_id=chain.chain_id,
            current_evidence_digest="hash123",
            caller_role="APPROVER"
        )
    assert "Role 'ADMINISTRATOR' required to execute remediation" in str(exc.value)


def test_governance_expired_approval_replay(tmp_path):
    """
    ATTACK: Adversary attempts to execute an approved proposal whose TTL has elapsed.
    DEFENSE: Time-to-live check detects expired approval, transitions chain to EXPIRED, and aborts.
    """
    db_file = str(tmp_path / "test_gov_expired.db")
    svc = ProofChainService(db_path=db_file)
    past_exp = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()

    chain = svc.create_investigation_chain(
        finding_id="F-S3-001",
        resource_arn="arn:aws:s3:::sensitive-data",
        evidence_id="EV-S3-001",
        evidence_digest="hash123",
        rule_id="SEC-S3-001",
        rule_version="1.0.0",
        rule_set_digest="rulehash",
        risk_score=90.0,
        risk_policy_version="2.0.0",
        remediation_action="enable_s3_block_public_access",
        parameters={"bucket_name": "sensitive-data"}
    )

    # Force approval record with past expiration
    record = svc.get_chain(chain.chain_id)
    record.lifecycle_state = ProposalLifecycleState.APPROVED
    record.approval_expires_at = past_exp
    svc._save_chain(record)

    # Attempt execution of expired proposal
    with pytest.raises(PermissionError) as exc:
        svc.execute_and_verify(
            chain_id=chain.chain_id,
            current_evidence_digest="hash123",
            caller_role="ADMINISTRATOR"
        )
    assert "Approval expired" in str(exc.value)

    # Verify state was transitioned to EXPIRED
    assert svc.get_chain(chain.chain_id).lifecycle_state == ProposalLifecycleState.EXPIRED


def test_governance_session_identity_validation(tmp_path):
    """
    ATTACK: Caller passes a valid session for 'alice' but claims approver is 'bob' (identity spoofing).
    DEFENSE: Session identity check enforces that session user must match requested approver.
    """
    db_file = str(tmp_path / "test_gov_session_spoof.db")
    svc = ProofChainService(db_path=db_file)
    future_exp = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()

    chain = svc.create_investigation_chain(
        finding_id="F-S3-001",
        resource_arn="arn:aws:s3:::sensitive-data",
        evidence_id="EV-S3-001",
        evidence_digest="hash123",
        rule_id="SEC-S3-001",
        rule_version="1.0.0",
        rule_set_digest="rulehash",
        risk_score=90.0,
        risk_policy_version="2.0.0",
        remediation_action="enable_s3_block_public_access",
        parameters={"bucket_name": "sensitive-data"}
    )

    # Create session for user 'alice'
    sess_id = create_session("alice")
    try:
        # Alice tries to approve claiming she is 'ciso_bob'
        with pytest.raises(PermissionError) as exc:
            svc.authorize_approval(
                chain_id=chain.chain_id,
                approver="ciso_bob",
                caller_role="APPROVER",
                expires_at=future_exp,
                session_id=sess_id
            )
        assert "Approver identity mismatch" in str(exc.value)

        # Alice approves as herself (legitimate)
        res = svc.authorize_approval(
            chain_id=chain.chain_id,
            approver="alice",
            caller_role="APPROVER",
            expires_at=future_exp,
            session_id=sess_id
        )
        assert res.lifecycle_state == ProposalLifecycleState.APPROVED
        assert res.approver_identity == "alice"
    finally:
        destroy_session(sess_id)


def test_governance_invalid_session_rejection(tmp_path):
    """
    ATTACK: Caller supplies a forged or non-existent session_id to approval endpoint.
    DEFENSE: System rejects the approval request with PermissionError.
    """
    db_file = str(tmp_path / "test_gov_bad_session.db")
    svc = ProofChainService(db_path=db_file)
    future_exp = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()

    chain = svc.create_investigation_chain(
        finding_id="F-S3-001",
        resource_arn="arn:aws:s3:::sensitive-data",
        evidence_id="EV-S3-001",
        evidence_digest="hash123",
        rule_id="SEC-S3-001",
        rule_version="1.0.0",
        rule_set_digest="rulehash",
        risk_score=90.0,
        risk_policy_version="2.0.0",
        remediation_action="enable_s3_block_public_access",
        parameters={"bucket_name": "sensitive-data"}
    )

    with pytest.raises(PermissionError) as exc:
        svc.authorize_approval(
            chain_id=chain.chain_id,
            approver="alice",
            caller_role="APPROVER",
            expires_at=future_exp,
            session_id="fake_forged_session_token_xyz"
        )
    assert "Invalid or expired approver session" in str(exc.value)


def test_governance_remediation_plan_hash_tamper_detection(tmp_path):
    """
    ATTACK: An attacker tampers with the remediation plan parameters between approval and execution.
    DEFENSE: Remediation plan digest mismatch is caught and logged.
    """
    db_file = str(tmp_path / "test_gov_plan_tamper.db")
    svc = ProofChainService(db_path=db_file)
    future_exp = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()

    chain = svc.create_investigation_chain(
        finding_id="F-S3-001",
        resource_arn="arn:aws:s3:::sensitive-data",
        evidence_id="EV-S3-001",
        evidence_digest="hash123",
        rule_id="SEC-S3-001",
        rule_version="1.0.0",
        rule_set_digest="rulehash",
        risk_score=90.0,
        risk_policy_version="2.0.0",
        remediation_action="enable_s3_block_public_access",
        parameters={"bucket_name": "sensitive-data"}
    )
    svc.authorize_approval(chain.chain_id, approver="admin", caller_role="APPROVER", expires_at=future_exp)

    # Pre-execution revalidation verifies evidence digest integrity
    # If attacker substitutes evidence digest:
    with pytest.raises(ValueError) as exc:
        svc.execute_and_verify(
            chain_id=chain.chain_id,
            current_evidence_digest="substituted_evidence_hash_bad",
            caller_role="ADMINISTRATOR"
        )
    assert "Evidence hash mismatch" in str(exc.value)
