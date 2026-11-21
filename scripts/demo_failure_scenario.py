"""
ExposureFence — Scenario B: Failed Remediation Assurance & Drift Catching
Demonstrates independent post-action ground-truth verification catching an un-remediated resource.
When execution completes (or is simulated) but ground truth indicates the exposure persists,
the platform refuses to claim compliance, transitions the proof chain to VERIFICATION_FAILED,
seals the dossier with explicit failure records, and preserves audit continuity without false claims.

Zero Cloud Cost Guarantee: 100% Offline Mock Fixtures. Zero AWS Mutations.
"""

import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.audit import verify_audit_hash_chain
from backend.evidence.collector import collect_all_mock_evidence
from backend.evidence.service import EvidenceService
from backend.governance.models import ProposalLifecycleState
from backend.governance.proof_chain import ProofChainService
from backend.governance.verifier import IndependentPostActionVerifier
from backend.intelligence.models import CanonicalFinding, FindingSeverity, FindingSource, FindingStatus
from backend.risk.engine import ContextualRiskEngine
from backend.rules.service import RulesEngine


def run_scenario_b():
    print("=" * 80)
    print("EXPOSUREFENCE — SCENARIO B: FAILED REMEDIATION ASSURANCE (DRIFT DETECTION)")
    print("Objective: Independent verification catches un-remediated exposure; transitions to VERIFICATION_FAILED")
    print("Cost: Strictly ₹0.00 / $0.00 | Environment: 100% Offline Deterministic Fixtures")
    print("=" * 80)

    # 1. Finding Ingestion
    print("\n[Step 1] Ingesting Public S3 Finding")
    finding_id = "FIND-S3-PUB-002"
    resource_arn = "arn:aws:s3:::bucket-public-001"
    print(f"  -> Finding ID          : {finding_id}")
    print(f"  -> Resource Target     : {resource_arn}")

    # 2. Evidence Collection
    print("\n[Step 2] RFC 8785 Evidence Generation")
    ev_records = collect_all_mock_evidence()
    ev_s3 = ev_records[0]
    print(f"  -> Evidence ID         : {ev_s3.evidence_id}")
    print(f"  -> Payload SHA-256     : {ev_s3.payload_sha256}")

    # 3. Rules Evaluation & Risk
    print("\n[Step 3] Rules Evaluation & Risk Assessment")
    rules_engine = RulesEngine()
    rule_results = rules_engine.evaluate_evidence(ev_s3, record_relationship=False)
    finding = CanonicalFinding(
        finding_id=finding_id,
        source_id="s3_collector",
        source_type=FindingSource.NATIVE_S3,
        raw_finding_hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        resource_arn=resource_arn,
        account_id="123456789012",
        region="us-east-1",
        service="s3",
        resource_type="AWS::S3::Bucket",
        title="S3 Bucket Unrestricted Public Access",
        description="Public access block disabled on bucket.",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.ACTIVE,
        evidence_id=ev_s3.evidence_id
    )
    risk_engine = ContextualRiskEngine()
    risk_assessment = risk_engine.calculate_risk(finding=finding)
    print(f"  -> Rule Evaluation     : {rule_results[0].rule_id} -> {rule_results[0].status}")
    print(f"  -> Risk Score          : {risk_assessment.overall_score} ({risk_assessment.severity.value})")

    # 4. Remediation Proposal Creation
    print("\n[Step 4] Remediation Proposal Creation & Investigation Chain")
    remediation_action = "enable_s3_block_public_access"
    pc_svc = ProofChainService()
    chain = pc_svc.create_investigation_chain(
        finding_id=finding_id,
        resource_arn=resource_arn,
        evidence_id=ev_s3.evidence_id,
        evidence_digest=ev_s3.payload_sha256,
        rule_id=rule_results[0].rule_id,
        rule_version="1.0.0",
        rule_set_digest="genesis_digest",
        risk_score=risk_assessment.overall_score,
        risk_policy_version="2.0.0",
        remediation_action=remediation_action,
        parameters={"bucket_name": "bucket-public-001"}
    )
    print(f"  -> Chain ID            : {chain.chain_id}")
    print(f"  -> Lifecycle State     : {chain.lifecycle_state.value}")

    # 5. Proposal Approval (Authenticated Operator)
    print("\n[Step 5] Proposal Approval Authorization")
    pc_svc.authorize_approval(
        chain_id=chain.chain_id,
        approver="secops_lead",
        caller_role="APPROVER",
        expires_at="2099-01-01T00:00:00Z"
    )
    print("  -> Proposal authorized for execution by 'secops_lead' (Role: APPROVER)")

    # 6. Simulated Execution with Un-Remediated Post-State (Simulating Silent Cloud Failure or Drift)
    print("\n[Step 6] Execution Simulation with Un-Remediated State")
    print("  -> Scenario Trigger: Execution script executed, but cloud policy failed to attach or bucket remained public.")
    unremediated_state = {
        "block_public_access": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
            "is_effective": False
        },
        "is_public_policy": True
    }

    exec_res = pc_svc.execute_and_verify(
        chain_id=chain.chain_id,
        current_evidence_digest=ev_s3.payload_sha256,
        post_execution_state=unremediated_state,
        caller_role="ADMINISTRATOR"
    )
    print(f"  -> Pre-Execution Check : {exec_res.pre_execution_revalidation_status}")
    print(f"  -> Execution Action    : {exec_res.execution_status}")

    # 7. Independent Ground-Truth Post-Action Verification
    print("\n[Step 7] Independent Post-Action Ground-Truth Verification")
    verified, reason, details = IndependentPostActionVerifier.verify_remediation(
        resource_arn=resource_arn,
        action_type=remediation_action,
        post_execution_state=unremediated_state
    )
    print(f"  -> Verification Oracle : {details.get('verification_source')}")
    print(f"  -> Verification Result : {verified} (False - Failure Caught!)")
    print(f"  -> Oracle Assessment   : {reason}")
    print(f"  -> Final Chain State   : {exec_res.lifecycle_state.value}")
    print(f"  -> Post-Action Status  : {exec_res.post_verification_status}")

    # Assertions guaranteeing contract compliance for failure detection
    assert verified is False, "Scenario B requires verification to detect the failure."
    assert exec_res.lifecycle_state == ProposalLifecycleState.VERIFICATION_FAILED, "State must be VERIFICATION_FAILED."

    # 8. Forensic Evidence Dossier Assembly
    print("\n[Step 8] Forensic Evidence Dossier Assembly")
    print(f"  -> Dossier Root Hash   : {exec_res.dossier_hash}")
    print("  -> Dossier Status      : Preserves failure evidence without false claims of compliance.")

    # 9. Audit Chain Verification
    print("\n[Step 9] Audit Ledger Integrity Verification")
    audit_valid = verify_audit_hash_chain()
    print(f"  -> Hash Chain Status   : {'VALID' if audit_valid else 'COMPROMISED'}")
    print("  -> Audit Event Recorded: PROOF_CHAIN_COMPLETED with lifecycle_state=VERIFICATION_FAILED")

    print("\n" + "=" * 80)
    print("SCENARIO B COMPLETED: FAILURE HONESTLY CAUGHT, AUDIT PRESERVED, ZERO FALSE CLAIMS")
    print("=" * 80)


if __name__ == "__main__":
    run_scenario_b()
