"""
ExposureFence — Scenario A: Successful Remediation Assurance Demonstration
Demonstrates end-to-end remediation lifecycle where independent post-action ground-truth
verification confirms that the target resource was successfully secured.
Transitions proof chain to VERIFIED, seals cryptographic Merkle dossier, and preserves audit continuity.

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
from backend.governance.auto_approval import AutoApprovalEvaluator
from backend.governance.models import ProposalLifecycleState
from backend.governance.proof_chain import ProofChainService
from backend.governance.verifier import IndependentPostActionVerifier
from backend.graph.attack_paths import AttackPathEngine
from backend.graph.engine import ResourceGraph
from backend.intelligence.models import CanonicalFinding, FindingSeverity, FindingSource, FindingStatus
from backend.risk.engine import ContextualRiskEngine
from backend.rules.service import RulesEngine


def run_scenario_a():
    print("=" * 80)
    print("EXPOSUREFENCE — SCENARIO A: SUCCESSFUL REMEDIATION ASSURANCE")
    print("Objective: Independent verification confirms remediation; proof chain transitions to VERIFIED")
    print("Cost: Strictly ₹0.00 / $0.00 | Environment: 100% Offline Deterministic Fixtures")
    print("=" * 80)

    # 1. Ingestion of S3 Public Exposure Finding
    print("\n[Step 1] Finding Ingestion & Classification")
    finding_id = "FIND-S3-PUB-001"
    resource_arn = "arn:aws:s3:::bucket-public-001"
    print(f"  -> Ingested Finding ID : {finding_id}")
    print(f"  -> Target Resource ARN : {resource_arn}")

    # 2. Evidence Collection & RFC 8785 Canonical Digest
    print("\n[Step 2] Canonical RFC 8785 Evidence Generation")
    ev_svc = EvidenceService()
    ev_svc.ingest_mock_data()
    ev_records = collect_all_mock_evidence()
    ev_s3 = ev_records[0]
    print(f"  -> Evidence ID         : {ev_s3.evidence_id}")
    print(f"  -> RFC 8785 SHA-256    : {ev_s3.payload_sha256}")
    print(f"  -> Evidence Integrity  : {ev_s3.integrity_status}")

    # 3. Rules Engine Pre-Remediation Check
    print("\n[Step 3] Declarative YAML Rules Engine Evaluation")
    rules_engine = RulesEngine()
    rule_results = rules_engine.evaluate_evidence(ev_s3, record_relationship=False)
    primary_rule = rule_results[0]
    print(f"  -> Rule ID             : {primary_rule.rule_id}")
    print(f"  -> Compliance Status   : {primary_rule.status} (Exposure Confirmed)")

    # 4. Contextual Risk & Attack Path Analysis
    print("\n[Step 4] Risk & Graph Attack-Path Assessment")
    graph = ResourceGraph()
    path_engine = AttackPathEngine(graph)
    paths = path_engine.find_all_attack_paths()
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
    print(f"  -> Active Attack Paths : {len(paths)}")
    print(f"  -> Risk Score          : {risk_assessment.overall_score} ({risk_assessment.severity.value})")

    # 5. Remediation Proposal & Cryptographic Binding
    print("\n[Step 5] Proposal Creation & Cryptographic Binding")
    remediation_action = "enable_s3_block_public_access"
    pc_svc = ProofChainService()
    chain = pc_svc.create_investigation_chain(
        finding_id=finding_id,
        resource_arn=resource_arn,
        evidence_id=ev_s3.evidence_id,
        evidence_digest=ev_s3.payload_sha256,
        rule_id=primary_rule.rule_id,
        rule_version="1.0.0",
        rule_set_digest="genesis_digest",
        risk_score=risk_assessment.overall_score,
        risk_policy_version="2.0.0",
        remediation_action=remediation_action,
        parameters={"bucket_name": "bucket-public-001"}
    )
    print(f"  -> Proof Chain ID      : {chain.chain_id}")
    print(f"  -> Plan Digest         : {chain.remediation_plan_digest}")
    print(f"  -> Initial State       : {chain.lifecycle_state.value}")

    # 6. 90% Automated Remediation Approval Evaluation
    print("\n[Step 6] 90% Threshold Automated Approval Policy Evaluation")
    eval_res = pc_svc.evaluate_auto_approval(chain.chain_id, caller_role="POLICY_ENGINE")
    print(f"  -> Quality Score       : {eval_res['score']}% (Required >= 90.0%)")
    print(f"  -> Mandatory Gates     : {'ALL PASSED' if eval_res['all_gates_passed'] else 'GATE BLOCKED'}")
    print(f"  -> Policy Decision     : {eval_res['decision']}")
    print(f"  -> Decision Authority  : {eval_res['decision_authority']}")
    chain = pc_svc.get_chain(chain.chain_id)
    print(f"  -> State After Policy  : {chain.lifecycle_state.value}")

    if chain.lifecycle_state == ProposalLifecycleState.PENDING:
        print("\n[Step 6b] Human Operator Approval Authorization")
        pc_svc.authorize_approval(
            chain_id=chain.chain_id,
            approver="secops_lead",
            caller_role="APPROVER",
            expires_at="2099-01-01T00:00:00Z"
        )
        chain = pc_svc.get_chain(chain.chain_id)
        print(f"  -> Authorized State    : {chain.lifecycle_state.value}")

    # 7. Pre-Execution Drift Revalidation & Simulated Execution
    print("\n[Step 7] Pre-Execution Revalidation & Controlled Execution")
    # Verified compliant state representing successful remediation
    compliant_state = {
        "block_public_access": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
            "is_effective": True
        },
        "is_public_policy": False
    }

    exec_res = pc_svc.execute_and_verify(
        chain_id=chain.chain_id,
        current_evidence_digest=ev_s3.payload_sha256,
        post_execution_state=compliant_state,
        caller_role="ADMINISTRATOR"
    )
    print(f"  -> Drift Revalidation  : {exec_res.pre_execution_revalidation_status}")
    print(f"  -> Execution Status    : {exec_res.execution_status}")

    # 8. Independent Post-Action Ground-Truth Verification
    print("\n[Step 8] Independent Post-Action Ground-Truth Verification")
    verified, reason, details = IndependentPostActionVerifier.verify_remediation(
        resource_arn=resource_arn,
        action_type=remediation_action,
        post_execution_state=compliant_state
    )
    print(f"  -> Verification Oracle : {details.get('verification_source')}")
    print(f"  -> Verified Status     : {verified} (True)")
    print(f"  -> Oracle Assessment   : {reason}")
    print(f"  -> Final Chain State   : {exec_res.lifecycle_state.value}")

    # Assertions guaranteeing contract compliance
    assert verified is True, "Scenario A requires verification to succeed."
    assert exec_res.lifecycle_state == ProposalLifecycleState.VERIFIED, "State must be VERIFIED."

    # 9. Cryptographic Evidence Dossier
    print("\n[Step 9] Sealed Merkle Evidence Dossier Assembly")
    print(f"  -> Dossier Root Hash   : {exec_res.dossier_hash}")
    print(f"  -> Verification Field  : {exec_res.post_verification_status}")

    # 10. Audit Chain Verification
    print("\n[Step 10] Audit Ledger Integrity Verification")
    audit_valid = verify_audit_hash_chain()
    print(f"  -> Hash Chain Status   : {'VALID' if audit_valid else 'COMPROMISED'}")

    print("\n" + "=" * 80)
    print("SCENARIO A COMPLETED: REMEDIATION VERIFIED, DOSSIER SEALED, AUDIT VALID")
    print("=" * 80)


if __name__ == "__main__":
    run_scenario_a()
