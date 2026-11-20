"""
ExposureFence — Governance & Evidence-to-Action Proof Chain Test Suite
Tests 14-state transition graph, AI boundary defenses, pre-execution revalidation,
stale approval replay protection (Scenario 4), independent verification failure (Scenario 6),
rollback plan generation, and cryptographic evidence dossier sealing.
"""

from datetime import datetime, timedelta, timezone
import pytest

from backend.governance.dossier import EvidenceDossierGenerator
from backend.governance.models import ProposalLifecycleState
from backend.governance.proof_chain import ProofChainService
from backend.governance.rollback import RollbackPlanGenerator
from backend.governance.state_machine import RemediationStateMachine
from backend.governance.verifier import IndependentPostActionVerifier


def test_state_machine_valid_transitions():
    state = ProposalLifecycleState.DRAFT
    state = RemediationStateMachine.transition(state, ProposalLifecycleState.PENDING, caller_role="INVESTIGATOR")
    assert state == ProposalLifecycleState.PENDING

    state = RemediationStateMachine.transition(state, ProposalLifecycleState.APPROVED, caller_role="APPROVER")
    assert state == ProposalLifecycleState.APPROVED

    state = RemediationStateMachine.transition(state, ProposalLifecycleState.READY_FOR_EXECUTION, caller_role="ADMIN")
    assert state == ProposalLifecycleState.READY_FOR_EXECUTION

    state = RemediationStateMachine.transition(state, ProposalLifecycleState.EXECUTING, caller_role="ADMIN")
    assert state == ProposalLifecycleState.EXECUTING

    state = RemediationStateMachine.transition(state, ProposalLifecycleState.EXECUTED, caller_role="ADMIN")
    assert state == ProposalLifecycleState.EXECUTED

    state = RemediationStateMachine.transition(state, ProposalLifecycleState.VERIFICATION_PENDING, caller_role="ADMIN")
    assert state == ProposalLifecycleState.VERIFICATION_PENDING

    state = RemediationStateMachine.transition(state, ProposalLifecycleState.VERIFIED, caller_role="ADMIN")
    assert state == ProposalLifecycleState.VERIFIED


def test_state_machine_ai_boundary_enforcement():
    """Verify that an AI Agent is mathematically prevented from approving its own proposal."""
    with pytest.raises(PermissionError) as excinfo:
        RemediationStateMachine.transition(
            current_state=ProposalLifecycleState.PENDING,
            target_state=ProposalLifecycleState.APPROVED,
            caller_role="ai_agent"
        )
    assert "AI Agent cannot approve" in str(excinfo.value)


def test_state_machine_invalid_transition():
    with pytest.raises(ValueError):
        RemediationStateMachine.transition(
            current_state=ProposalLifecycleState.PENDING,
            target_state=ProposalLifecycleState.EXECUTED,
            caller_role="ADMIN"
        )


def test_state_machine_expiration_blocks_approval():
    past_timestamp = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    with pytest.raises(PermissionError) as excinfo:
        RemediationStateMachine.transition(
            current_state=ProposalLifecycleState.PENDING,
            target_state=ProposalLifecycleState.APPROVED,
            caller_role="APPROVER",
            expires_at=past_timestamp
        )
    assert "expired" in str(excinfo.value)


def test_rollback_plan_generation():
    rollback = RollbackPlanGenerator.generate_rollback(
        action_type="enable_s3_block_public_access",
        resource_arn="arn:aws:s3:::corp-finance-public-export",
        parameters={"bucket_name": "corp-finance-public-export"}
    )
    assert rollback["rollback_action"] == "restore_previous_s3_public_access_block"
    assert "rollback_digest" in rollback
    assert len(rollback["rollback_digest"]) == 64


def test_scenario_4_stale_approval_replay(tmp_path):
    """
    Scenario 4 Verification:
    Stale approval replay / Evidence alteration before execution.
    Pre-execution revalidation catches evidence mismatch and invalidates approval.
    """
    db_file = str(tmp_path / "test_pc.db")
    svc = ProofChainService(db_path=db_file)

    future_exp = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    chain = svc.create_investigation_chain(
        finding_id="F-S3-001",
        resource_arn="arn:aws:s3:::corp-finance-public-export",
        evidence_id="EV-S3-001",
        evidence_digest="original_hash_12345",
        rule_id="SEC-S3-001",
        rule_version="1.0.0",
        rule_set_digest="rules_hash_abc",
        risk_score=90.0,
        risk_policy_version="2.0.0",
        remediation_action="enable_s3_block_public_access",
        parameters={"bucket_name": "corp-finance-public-export"}
    )

    # Approve
    svc.authorize_approval(chain.chain_id, approver="ciso-officer", caller_role="APPROVER", expires_at=future_exp)

    # Now attempt to execute, but evidence has drifted/tampered (evidence hash changed)
    with pytest.raises(ValueError) as excinfo:
        svc.execute_and_verify(
            chain_id=chain.chain_id,
            current_evidence_digest="tampered_or_drifted_hash_99999",
            post_execution_state={"block_public_access": {"is_effective": True}}
        )
    assert "Pre-execution revalidation failed" in str(excinfo.value)

    # Verify state was marked INVALIDATED
    persisted = svc.get_chain(chain.chain_id)
    assert persisted.lifecycle_state == ProposalLifecycleState.INVALIDATED
    assert persisted.pre_execution_revalidation_status == "FAILED_EVIDENCE_MISMATCH"


def test_scenario_6_independent_verification_failure(tmp_path):
    """
    Scenario 6 Verification:
    Remediation is simulated, but independent verification finds the exposure was NOT resolved.
    Ensures state transitions to VERIFICATION_FAILED rather than claiming compliance.
    """
    db_file = str(tmp_path / "test_pc_fail.db")
    svc = ProofChainService(db_path=db_file)

    future_exp = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    chain = svc.create_investigation_chain(
        finding_id="F-S3-001",
        resource_arn="arn:aws:s3:::corp-finance-public-export",
        evidence_id="EV-S3-001",
        evidence_digest="valid_hash_12345",
        rule_id="SEC-S3-001",
        rule_version="1.0.0",
        rule_set_digest="rules_hash_abc",
        risk_score=90.0,
        risk_policy_version="2.0.0",
        remediation_action="enable_s3_block_public_access",
        parameters={"bucket_name": "corp-finance-public-export"}
    )
    svc.authorize_approval(chain.chain_id, approver="sec-admin", caller_role="APPROVER", expires_at=future_exp)

    # Incomplete remediation state: public policy still active!
    incomplete_state = {
        "block_public_access": {"is_effective": False},
        "is_public_policy": True
    }

    result = svc.execute_and_verify(
        chain_id=chain.chain_id,
        current_evidence_digest="valid_hash_12345",
        post_execution_state=incomplete_state
    )

    assert result.lifecycle_state == ProposalLifecycleState.VERIFICATION_FAILED
    assert "Verification Failed" in result.post_verification_status
    assert result.dossier_hash is not None


def test_scenario_6_independent_verification_success(tmp_path):
    db_file = str(tmp_path / "test_pc_succ.db")
    svc = ProofChainService(db_path=db_file)

    future_exp = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    chain = svc.create_investigation_chain(
        finding_id="F-S3-001",
        resource_arn="arn:aws:s3:::corp-finance-public-export",
        evidence_id="EV-S3-001",
        evidence_digest="valid_hash_12345",
        rule_id="SEC-S3-001",
        rule_version="1.0.0",
        rule_set_digest="rules_hash_abc",
        risk_score=90.0,
        risk_policy_version="2.0.0",
        remediation_action="enable_s3_block_public_access",
        parameters={"bucket_name": "corp-finance-public-export"}
    )
    svc.authorize_approval(chain.chain_id, approver="sec-admin", caller_role="APPROVER", expires_at=future_exp)

    # Complete remediation state: effective BPA, no public policy
    secure_state = {
        "block_public_access": {"is_effective": True},
        "is_public_policy": False
    }

    result = svc.execute_and_verify(
        chain_id=chain.chain_id,
        current_evidence_digest="valid_hash_12345",
        post_execution_state=secure_state
    )

    assert result.lifecycle_state == ProposalLifecycleState.VERIFIED
    assert result.post_verification_status == "VERIFIED"
    assert result.dossier_hash is not None


def test_dossier_generation_and_tamper_detection():
    pkg = EvidenceDossierGenerator.generate_dossier(
        proof_chain_record={"chain_id": "CHN-123", "approver_identity": "admin", "approval_timestamp": "now", "lifecycle_state": "VERIFIED"},
        finding_details={"finding_id": "F-01", "resource_arn": "arn:aws:s3:::b1", "severity": "HIGH"},
        evidence_record={"evidence_id": "EV-01", "payload_sha256": "hash", "integrity_status": "VERIFIED"},
        rule_evaluation={"rule_id": "SEC-S3-001", "status": "FAIL"},
        risk_score_details={"overall_score": 85.0, "severity": "HIGH", "component_breakdown": {}},
        remediation_plan={"action_type": "enable_s3_bpa", "plan_digest": "plan_hash"}
    )

    # Valid package
    assert EvidenceDossierGenerator.verify_dossier(pkg) is True

    # Tampered package
    pkg["dossier"]["target"]["severity"] = "LOW_TAMPERED"
    assert EvidenceDossierGenerator.verify_dossier(pkg) is False
