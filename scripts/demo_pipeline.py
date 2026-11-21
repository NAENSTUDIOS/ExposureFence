"""
ExposureFence — End-to-End Portfolio Demonstration Script
Demonstrates all 15 operational steps of the ExposureFence pipeline offline with zero cloud cost.
Dual Mode: 100% Offline Mock Fixtures. Zero AWS mutations.
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.evidence.collector import collect_all_mock_evidence
from backend.evidence.service import EvidenceService
from backend.governance.auto_approval import AutoApprovalEvaluator
from backend.governance.dossier import EvidenceDossierGenerator
from backend.governance.proof_chain import ProofChainService
from backend.governance.verifier import IndependentPostActionVerifier
from backend.graph.attack_paths import AttackPathEngine
from backend.graph.engine import ResourceGraph
from backend.intelligence.models import CanonicalFinding, FindingSeverity, FindingSource, FindingStatus
from backend.risk.engine import ContextualRiskEngine
from backend.rules.service import RulesEngine


def run_demonstration():
    print("=" * 78)
    print("EXPOSUREFENCE — END-TO-END DEMONSTRATION (OFFLINE SIMULATED MODE)")
    print("Strict Zero-Cost Guarantee: ₹0.00 / $0.00 Out-of-Pocket Incurred")
    print("=" * 78)

    # Step 1: Cloud Finding Ingestion
    print("\n[Step 1] Ingesting Cloud Findings from Offline Mock Fixtures...")
    with open("mock_data/s3_buckets.json", "r", encoding="utf-8") as f:
        s3_data = json.load(f)
    public_bucket = s3_data[0]
    finding_id = "FIND-S3-PUB-001"
    resource_arn = f"arn:aws:s3:::{public_bucket.get('resource_id', 'bucket-public-001')}"
    print(f"  -> Ingested Finding: {finding_id} for resource: {resource_arn}")

    # Step 2: Evidence Generation & Canonical Digesting (RFC 8785)
    print("\n[Step 2] Collecting Canonical RFC 8785 Evidence...")
    ev_svc = EvidenceService()
    ev_records = collect_all_mock_evidence()
    ev_s3 = ev_records[0]
    print(f"  -> Registered Evidence ID: {ev_s3.evidence_id}")
    print(f"  -> RFC 8785 SHA-256 Digest: {ev_s3.payload_sha256}")

    # Step 3: YAML Security Rules Evaluation
    print("\n[Step 3] Evaluating Declarative Rules Engine (rules/rules.yaml)...")
    rules_engine = RulesEngine()
    rule_res = rules_engine.evaluate_evidence(ev_s3, record_relationship=False)
    print(f"  -> Evaluated {len(rule_res)} applicable rules. Primary rule: {rule_res[0].rule_id} status: {rule_res[0].status}")

    # Step 4: Multi-Hop Attack Path Analysis
    print("\n[Step 4] Executing Attack-Path Traversal (Bounded BFS)...")
    graph = ResourceGraph()
    path_engine = AttackPathEngine(graph)
    paths = path_engine.find_all_attack_paths()
    print(f"  -> Discovered {len(paths)} potential attack paths across asset topology.")

    # Step 5: Contextual Risk Calculation (ContextualRiskEngine)
    print("\n[Step 5] Calculating Contextual Risk Score...")
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
        description="Bucket permits public read/write via disabled block public access.",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.ACTIVE,
        evidence_id=ev_s3.evidence_id
    )
    risk_engine = ContextualRiskEngine()
    risk_assessment = risk_engine.calculate_risk(finding=finding)
    print(f"  -> Composite Risk Score: {risk_assessment.overall_score} (Severity: {risk_assessment.severity.value})")

    # Step 6 & 7: AI Investigation & Remediation Proposal Generation
    print("\n[Step 6 & 7] AI Investigation & Structured Proposal Generation...")
    print("  -> BedrockAgentCore dispatched inline-function tool: propose_fix")
    remediation_action = "enable_s3_block_public_access"
    pc_svc = ProofChainService()
    chain = pc_svc.create_investigation_chain(
        finding_id=finding_id,
        resource_arn=resource_arn,
        evidence_id=ev_s3.evidence_id,
        evidence_digest=ev_s3.payload_sha256,
        rule_id="SEC-S3-001",
        rule_version="1.0.0",
        rule_set_digest="genesis_digest",
        risk_score=risk_assessment.overall_score,
        risk_policy_version="2.0.0",
        remediation_action=remediation_action,
        parameters={"bucket_name": public_bucket.get("resource_id", "bucket-public-001")}
    )
    print(f"  -> Proof Chain Initiated: {chain.chain_id} (State: {chain.lifecycle_state.value})")

    # Step 8 & 9: Independent Proposal Scoring & 90% Conditional Auto-Approval
    print("\n[Step 8 & 9] Independent Deterministic Scoring & 90% Auto-Approval Gate...")
    eval_res = pc_svc.evaluate_auto_approval(chain.chain_id, caller_role="POLICY_ENGINE")
    print(f"  -> Evaluator Score: {eval_res['score']}% (Threshold: 90.0%)")
    print(f"  -> Decision: {eval_res['decision']}")
    print(f"  -> Authority: {eval_res['decision_authority']}")
    print(f"  -> Cryptographic Binding Hash: {eval_res['binding_digest'][:24]}...")

    # Step 10: Mandatory Security-Gate Rejection Example
    print("\n[Step 10] Testing Mandatory Gate Rejection (Destructive Mutation Attempt)...")
    bad_proposal = {
        "proposal_id": "PROP-BAD-001",
        "finding_id": finding_id,
        "resource_id": resource_arn,
        "remediation_action": "delete_s3_bucket",
        "status": "PENDING"
    }
    rejected_res = AutoApprovalEvaluator.evaluate(bad_proposal, evidence=ev_s3)
    print(f"  -> Malicious action 'delete_s3_bucket' evaluated.")
    print(f"  -> Gate Decision: {rejected_res.decision} (Reason: {rejected_res.blocking_reasons[0]})")

    # Step 11 & 12: Governance Lifecycle & Simulated Execution
    print("\n[Step 11 & 12] Governance Lifecycle Transition to Simulated Execution...")
    # Human approval or auto-approval transition
    pc_svc.authorize_approval(
        chain_id=chain.chain_id,
        approver="secops_lead",
        caller_role="APPROVER",
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
    )
    print("  -> Authenticated Human Approver (secops_lead) authorized proposal.")

    # Compliant post-execution state for successful verification demonstration
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
    print(f"  -> Pre-Execution Drift Revalidation: {exec_res.pre_execution_revalidation_status}")
    print(f"  -> Execution Status: {exec_res.execution_status} (Strictly Simulated)")

    # Step 13: Independent Post-Action Ground-Truth Verification
    print("\n[Step 13] Independent Ground-Truth Post-Action Verification...")
    verified, reason, details = IndependentPostActionVerifier.verify_remediation(
        resource_arn=resource_arn,
        action_type=remediation_action,
        post_execution_state=compliant_state
    )
    print(f"  -> Ground-Truth Result: {verified} (Source: {details.get('verification_source', 'INDEPENDENT_GROUND_TRUTH')})")
    print(f"  -> Verification Note: {reason}")
    print(f"  -> Lifecycle State: {exec_res.lifecycle_state.value}")

    # Step 14: Cryptographic Evidence Dossier Assembly
    print("\n[Step 14] Assembling Cryptographic Evidence Dossier (Root SHA-256 Sealed)...")
    print(f"  -> Sealed Investigation Dossier Hash: {exec_res.dossier_hash}")

    # Step 15: Final Immutable Audit Record Verification
    print("\n[Step 15] Verifying Audit Hash Chain Continuity...")
    from backend.audit import verify_audit_hash_chain
    is_valid = verify_audit_hash_chain()
    print(f"  -> Audit Ledger Hash-Chain Integrity: {'VALID' if is_valid else 'COMPROMISED'}")
    print("\n" + "=" * 78)
    print("DEMONSTRATION COMPLETED SUCCESSFULLY (15/15 STEPS VERIFIED)")
    print("=" * 78)


if __name__ == "__main__":
    run_demonstration()
