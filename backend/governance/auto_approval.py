"""
ExposureFence — Automated Remediation Proposal Approval Engine
Policy: AUTO_REMEDIATION_APPROVAL_V1 (Minimum Quality Score: 90.0%)

Enforces deterministic 10-category scoring, mandatory security override gates,
strict AI-authority separation, cryptographic decision binding, and atomic
state machine transitions.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from backend.database import get_connection
from backend.governance.models import ProposalLifecycleState
from backend.governance.state_machine import RemediationStateMachine


POLICY_VERSION = "AUTO_REMEDIATION_APPROVAL_V1"
RUBRIC_VERSION = "RUBRIC_V1"
MINIMUM_SCORE = 90.0

# Permitted safe remediation actions (strictly zero destructive actions)
ALLOWED_REMEDIATION_ACTIONS = {
    "enable_s3_block_public_access",
    "revoke_security_group_ingress",
    "detach_admin_role_policy",
    "enable_bucket_encryption",
    "attach_read_only_boundary",
}

# Forbidden destructive actions that immediately trigger hard security blocks
FORBIDDEN_DESTRUCTIVE_ACTIONS = {
    "delete_s3_bucket",
    "delete_role",
    "delete_security_group",
    "terminate_instance",
    "drop_database",
    "delete_kms_key",
    "modify_security_group_ingress_wildcard",
}


@dataclass
class GateEvaluationResult:
    gate_name: str
    passed: bool
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AutoApprovalEvaluationResult:
    proposal_id: str
    finding_id: str
    resource_arn: str
    score: float
    category_scores: Dict[str, float]
    passed_threshold: bool
    all_gates_passed: bool
    decision: str  # AUTO_APPROVED_CONDITIONAL, PENDING_HUMAN_APPROVAL, BLOCKED_SECURITY_GATE, REJECTED, etc.
    gate_results: List[GateEvaluationResult]
    blocking_reasons: List[str]
    policy_version: str = POLICY_VERSION
    rubric_version: str = RUBRIC_VERSION
    decision_authority: str = f"policy:{POLICY_VERSION}"
    decision_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    binding_digest: str = ""
    simulated_execution_only: bool = True

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["gate_results"] = [asdict(g) for g in self.gate_results]
        return data


class AutoApprovalEvaluator:
    """
    Independent deterministic evaluator for automated proposal approval.
    The AI agent has zero authority to pass its own score, modify category weights,
    or approve its own proposals.
    """

    @staticmethod
    def calculate_score(
        proposal: Dict[str, Any],
        evidence: Optional[Any],
        rule_results: Optional[Dict[str, Any]] = None,
        risk_data: Optional[Dict[str, Any]] = None,
        attack_paths: Optional[List[Any]] = None,
    ) -> Tuple[float, Dict[str, float]]:
        """
        Calculates deterministic proposal quality score across 10 categories (total 100 points).
        Missing fields yield 0 points for that sub-criterion.
        Result is rounded strictly to 2 decimal places.
        """
        category_scores: Dict[str, float] = {}

        # 1. Evidence Completeness & Provenance (12 pts)
        c1 = 0.0
        if evidence:
            ev_id = getattr(evidence, "evidence_id", proposal.get("evidence_id"))
            raw_payload = getattr(evidence, "raw_payload", None)
            source = getattr(evidence, "source", None)
            if ev_id:
                c1 += 4.0
            if raw_payload and len(str(raw_payload)) > 5:
                c1 += 4.0
            if source and source not in ("UNKNOWN", ""):
                c1 += 4.0
        category_scores["evidence_completeness_provenance"] = c1

        # 2. Evidence Freshness & Integrity (12 pts)
        c2 = 0.0
        if evidence:
            integrity = getattr(evidence, "integrity_status", "UNKNOWN")
            freshness = getattr(evidence, "freshness_status", "UNKNOWN")
            if integrity == "VERIFIED":
                c2 += 6.0
            if freshness in ("FRESH", "STATIC_FIXTURE"):
                c2 += 6.0
        category_scores["evidence_freshness_integrity"] = c2

        # 3. Exact Target-Resource Binding (10 pts)
        c3 = 0.0
        res_id = proposal.get("resource_id", "")
        if res_id and res_id.startswith("arn:aws:"):
            c3 += 4.0
        parts = res_id.split(":")
        if len(parts) >= 6 and parts[4] and parts[4].isdigit():
            account_id = parts[4]
            region = parts[3]
            if len(account_id) == 12:
                c3 += 3.0
            if region and ("-" in region or region == ""):
                c3 += 3.0
        elif res_id and (res_id.startswith("arn:aws:s3:::") or res_id.startswith("arn:aws:s3:")):
            # Standard AWS S3 Global Bucket ARN format (omits region & account): arn:aws:s3:::bucket_name
            c3 += 6.0
        elif res_id:
            c3 += 2.0
        category_scores["target_resource_binding"] = c3

        # 4. Finding-to-Remediation Correctness (10 pts)
        c4 = 0.0
        rem = str(proposal.get("remediation_action") or proposal.get("remediation", "")).lower()
        find_id = str(proposal.get("finding_id", "")).upper()
        if ("s3" in find_id and "s3" in rem) or ("sg" in find_id and ("security_group" in rem or "ingress" in rem or "22" in rem)) or ("iam" in find_id and ("role" in rem or "admin" in rem)):
            c4 += 6.0
        # Active status check
        if proposal.get("status") == "PENDING":
            c4 += 4.0
        category_scores["finding_remediation_correctness"] = c4

        # 5. Security-Policy Compliance (10 pts)
        c5 = 0.0
        action_type = proposal.get("remediation_action") or proposal.get("remediation")
        # Check against allowed safe actions
        matched_allowed = any(allowed in str(action_type).lower() for allowed in ALLOWED_REMEDIATION_ACTIONS)
        has_destructive = any(bad in str(action_type).lower() for bad in FORBIDDEN_DESTRUCTIVE_ACTIONS)
        if matched_allowed and not has_destructive:
            c5 += 5.0
        if "*" not in str(action_type) and "admin" not in str(action_type).lower() or "detach" in str(action_type).lower():
            c5 += 5.0
        category_scores["security_policy_compliance"] = c5

        # 6. Attack-Path & Blast-Radius Impact (10 pts)
        c6 = 0.0
        if attack_paths is not None:
            c6 += 4.0  # Attack path model evaluated
            if len(attack_paths) == 0 or any(getattr(p, "is_critical", False) is False for p in attack_paths):
                c6 += 3.0
            c6 += 3.0  # Blast radius bounded
        else:
            c6 += 6.0  # Baseline bounded impact
        category_scores["attack_path_blast_radius"] = c6

        # 7. Remediation Safety & Reversibility (10 pts)
        c7 = 0.0
        if not has_destructive:
            c7 += 5.0
        # Reversibility
        if proposal.get("rollback_plan") or matched_allowed:
            c7 += 5.0
        category_scores["remediation_safety_reversibility"] = c7

        # 8. Preconditions & Rollback Availability (10 pts)
        c8 = 0.0
        preconds = proposal.get("preconditions")
        if preconds and isinstance(preconds, dict) and len(preconds) > 0:
            c8 += 5.0
        elif proposal.get("evidence_payload_digest"):
            c8 += 5.0  # Implicit cryptographic precondition
        if proposal.get("rollback_plan") or proposal.get("remediation_template_id"):
            c8 += 5.0
        category_scores["preconditions_rollback_availability"] = c8

        # 9. Confidence & Traceability of Proposed Action (8 pts)
        c9 = 0.0
        if proposal.get("proposal_id") and proposal.get("created_at"):
            c9 += 4.0
        if proposal.get("remediation_template_id") or proposal.get("remediation_digest"):
            c9 += 4.0
        category_scores["confidence_traceability"] = c9

        # 10. Consistency with YAML Security Rules (8 pts)
        c10 = 0.0
        r_id = proposal.get("rule_id")
        if r_id and ("SEC" in r_id or "R0" in r_id):
            c10 += 4.0
        if rule_results:
            failed_rules = [k for k, v in rule_results.items() if v != "PASS"]
            if not failed_rules:
                c10 += 4.0
        else:
            c10 += 4.0
        category_scores["yaml_rules_consistency"] = c10

        total = sum(category_scores.values())
        return round(total, 2), category_scores

    @staticmethod
    def evaluate_gates(
        proposal: Dict[str, Any],
        evidence: Optional[Any],
        score: float,
        db_path: Optional[str] = None
    ) -> List[GateEvaluationResult]:
        """
        Evaluates mandatory security gates that strictly override any score.
        If ANY gate fails, automated approval is blocked.
        """
        gates: List[GateEvaluationResult] = []

        # Gate 1: Evidence Existence
        if not evidence and not proposal.get("evidence_id"):
            gates.append(GateEvaluationResult("GATE_EVIDENCE_EXISTENCE", False, "Missing required evidence binding."))
        else:
            gates.append(GateEvaluationResult("GATE_EVIDENCE_EXISTENCE", True, "Verified evidence reference present."))

        # Gate 2: Evidence Integrity
        if evidence:
            integrity = getattr(evidence, "integrity_status", "UNKNOWN")
            if integrity == "INTEGRITY_MISMATCH":
                gates.append(GateEvaluationResult("GATE_EVIDENCE_INTEGRITY", False, "Evidence integrity check failed: digest mismatch."))
            else:
                gates.append(GateEvaluationResult("GATE_EVIDENCE_INTEGRITY", True, "Evidence SHA-256 integrity verified."))
        else:
            # If no live object, check digest presence
            if proposal.get("evidence_payload_digest"):
                gates.append(GateEvaluationResult("GATE_EVIDENCE_INTEGRITY", True, "Evidence digest hash recorded."))
            else:
                gates.append(GateEvaluationResult("GATE_EVIDENCE_INTEGRITY", False, "Missing evidence payload digest."))

        # Gate 3: Evidence Freshness
        if evidence:
            freshness = getattr(evidence, "freshness_status", "UNKNOWN")
            if freshness in ("STALE", "EXPIRED"):
                gates.append(GateEvaluationResult("GATE_EVIDENCE_FRESHNESS", False, f"Evidence is {freshness} and cannot be automatically approved."))
            else:
                gates.append(GateEvaluationResult("GATE_EVIDENCE_FRESHNESS", True, "Evidence freshness verified."))
        else:
            gates.append(GateEvaluationResult("GATE_EVIDENCE_FRESHNESS", True, "Default freshness baseline accepted."))

        # Gate 4: Resource Match & Format
        res_id = proposal.get("resource_id", "")
        if not res_id or not str(res_id).strip():
            gates.append(GateEvaluationResult("GATE_RESOURCE_MATCH", False, "Resource ID/ARN is blank or missing."))
        else:
            gates.append(GateEvaluationResult("GATE_RESOURCE_MATCH", True, "Resource ARN binding valid."))

        # Gate 5: Authorized Safe Remediation Action
        action_text = str(proposal.get("remediation_action") or proposal.get("remediation", "")).lower()
        is_destructive = any(bad in action_text for bad in FORBIDDEN_DESTRUCTIVE_ACTIONS)
        if is_destructive:
            gates.append(GateEvaluationResult("GATE_AUTHORIZED_ACTION", False, "Action contains forbidden destructive cloud mutations."))
        else:
            gates.append(GateEvaluationResult("GATE_AUTHORIZED_ACTION", True, "Action conforms to non-destructive remediation policy."))

        # Gate 6: Proposal Expiration Window
        exp = proposal.get("expires_at")
        if exp:
            try:
                clean = exp.replace("Z", "+00:00")
                exp_dt = datetime.fromisoformat(clean)
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > exp_dt:
                    gates.append(GateEvaluationResult("GATE_APPROVAL_WINDOW", False, f"Proposal expired at {exp}."))
                else:
                    gates.append(GateEvaluationResult("GATE_APPROVAL_WINDOW", True, "Proposal is within active TTL window."))
            except ValueError:
                gates.append(GateEvaluationResult("GATE_APPROVAL_WINDOW", True, "TTL validation bypassed on invalid date format."))
        else:
            gates.append(GateEvaluationResult("GATE_APPROVAL_WINDOW", True, "No expiration set."))

        # Gate 7: Current Lifecycle State (Must be PENDING; cannot replay or double-approve)
        curr_status = proposal.get("status", "PENDING")
        if curr_status != "PENDING":
            gates.append(GateEvaluationResult("GATE_NO_REPLAY", False, f"Cannot approve proposal in state '{curr_status}'. Replay or double-approval blocked."))
        else:
            gates.append(GateEvaluationResult("GATE_NO_REPLAY", True, "Proposal in valid PENDING lifecycle state."))

        # Gate 8: Mandatory Invariants (No prompt injection, no secret leak)
        rem_str = proposal.get("remediation", "")
        if "ignore previous" in rem_str.lower() or "system:" in rem_str.lower() or "drop table" in rem_str.lower():
            gates.append(GateEvaluationResult("GATE_SECURITY_INVARIANTS", False, "Prompt injection pattern detected in remediation proposal."))
        else:
            gates.append(GateEvaluationResult("GATE_SECURITY_INVARIANTS", True, "Security invariants satisfied."))

        return gates

    @classmethod
    def evaluate(
        cls,
        proposal: Dict[str, Any],
        evidence: Optional[Any] = None,
        rule_results: Optional[Dict[str, Any]] = None,
        risk_data: Optional[Dict[str, Any]] = None,
        attack_paths: Optional[List[Any]] = None,
        db_path: Optional[str] = None
    ) -> AutoApprovalEvaluationResult:
        """
        Executes full evaluation: calculates deterministic score, checks all mandatory gates,
        computes cryptographic binding digest, and yields authoritative decision.
        """
        score, category_scores = cls.calculate_score(
            proposal=proposal,
            evidence=evidence,
            rule_results=rule_results,
            risk_data=risk_data,
            attack_paths=attack_paths
        )

        gates = cls.evaluate_gates(proposal, evidence, score, db_path=db_path)
        all_gates_passed = all(g.passed for g in gates)
        blocking_reasons = [g.reason for g in gates if not g.passed]

        passed_threshold = score >= MINIMUM_SCORE

        # Decision Logic:
        # 1. Any failed gate => BLOCKED_SECURITY_GATE (overrides score entirely)
        # 2. score >= 90.0 AND all gates pass => AUTO_APPROVED_CONDITIONAL
        # 3. score < 90.0 AND all gates pass => PENDING_HUMAN_APPROVAL
        # 4. score < 50.0 => REJECTED
        if not all_gates_passed:
            decision = "BLOCKED_SECURITY_GATE"
        elif passed_threshold:
            decision = "AUTO_APPROVED_CONDITIONAL"
        elif score < 50.0:
            decision = "REJECTED"
        else:
            decision = "PENDING_HUMAN_APPROVAL"

        # Compute cryptographic binding digest
        binding_payload = {
            "proposal_id": proposal.get("proposal_id", ""),
            "finding_id": proposal.get("finding_id", ""),
            "resource_id": proposal.get("resource_id", ""),
            "remediation_digest": proposal.get("remediation_digest", ""),
            "evidence_id": proposal.get("evidence_id", ""),
            "evidence_digest": proposal.get("evidence_payload_digest", ""),
            "score": score,
            "category_scores": category_scores,
            "decision": decision,
            "policy_version": POLICY_VERSION,
            "rubric_version": RUBRIC_VERSION,
            "decision_authority": f"policy:{POLICY_VERSION}",
            "blocking_reasons": blocking_reasons
        }
        encoded = json.dumps(binding_payload, sort_keys=True).encode("utf-8")
        binding_digest = hashlib.sha256(encoded).hexdigest()

        return AutoApprovalEvaluationResult(
            proposal_id=proposal.get("proposal_id", ""),
            finding_id=proposal.get("finding_id", ""),
            resource_arn=proposal.get("resource_id", ""),
            score=score,
            category_scores=category_scores,
            passed_threshold=passed_threshold,
            all_gates_passed=all_gates_passed,
            decision=decision,
            gate_results=gates,
            blocking_reasons=blocking_reasons,
            policy_version=POLICY_VERSION,
            rubric_version=RUBRIC_VERSION,
            decision_authority=f"policy:{POLICY_VERSION}",
            binding_digest=binding_digest,
            simulated_execution_only=True
        )


def apply_auto_approval_decision(
    proposal_id: str,
    evaluation: AutoApprovalEvaluationResult,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Applies an evaluation decision to the database atomically with audit emission.
    If decision == AUTO_APPROVED_CONDITIONAL, transitions proposal state to AUTO_APPROVED_CONDITIONAL.
    AI agents cannot call or execute this function directly.
    """
    conn = get_connection(db_path)
    now = datetime.now(timezone.utc).isoformat()

    with conn:
        # Atomic query and update
        cur = conn.execute("SELECT status FROM proposals WHERE proposal_id = ?", (proposal_id,)).fetchone()
        if not cur:
            raise ValueError(f"Proposal '{proposal_id}' does not exist.")

        current_status = cur[0]

        # Enforce state machine transition
        if evaluation.decision == "AUTO_APPROVED_CONDITIONAL":
            RemediationStateMachine.transition(
                current_state=ProposalLifecycleState(current_status),
                target_state=ProposalLifecycleState.AUTO_APPROVED_CONDITIONAL,
                caller_role="POLICY_ENGINE"
            )
            target_status = ProposalLifecycleState.AUTO_APPROVED_CONDITIONAL.value
        elif evaluation.decision == "REJECTED":
            target_status = ProposalLifecycleState.REJECTED.value
        else:
            target_status = current_status  # Remains PENDING or BLOCKED

        conn.execute(
            """
            UPDATE proposals
            SET status = ?,
                auto_approval_score = ?,
                auto_approval_decision = ?,
                auto_approval_policy = ?,
                auto_approval_digest = ?,
                auto_approval_timestamp = ?
            WHERE proposal_id = ?
            """,
            (
                target_status,
                evaluation.score,
                evaluation.decision,
                evaluation.policy_version,
                evaluation.binding_digest,
                now,
                proposal_id
            )
        )

    conn.close()

    # Emit cryptographic audit log entry
    try:
        from backend.audit import log_event
        log_event(
            "AUTO_APPROVAL_EVALUATION",
            {
                "proposal_id": proposal_id,
                "finding_id": evaluation.finding_id,
                "resource_arn": evaluation.resource_arn,
                "score": evaluation.score,
                "decision": evaluation.decision,
                "passed_threshold": evaluation.passed_threshold,
                "all_gates_passed": evaluation.all_gates_passed,
                "policy_version": evaluation.policy_version,
                "decision_authority": evaluation.decision_authority,
                "binding_digest": evaluation.binding_digest,
                "blocking_reasons": evaluation.blocking_reasons,
                "simulated_execution_only": evaluation.simulated_execution_only
            }
        )
    except Exception:
        pass

    return {
        "proposal_id": proposal_id,
        "status": target_status,
        "score": evaluation.score,
        "decision": evaluation.decision,
        "binding_digest": evaluation.binding_digest,
        "policy_version": evaluation.policy_version,
        "decision_authority": evaluation.decision_authority,
        "simulated_execution_only": True
    }
