"""
ExposureFence — Evidence-to-Action Proof Chain Orchestration Service
Coordinates the end-to-end 20-step investigation lifecycle from initial finding through
evidence, rule evaluation, contextual risk, attack paths, human approval, simulated execution,
independent post-action verification, and cryptographic dossier packaging.
"""

from datetime import datetime, timezone
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional
import uuid

from backend.database import get_connection
from backend.governance.dossier import EvidenceDossierGenerator
from backend.governance.models import (
    ProofChainRecord,
    ProposalLifecycleState,
    RemediationPlan,
)
from backend.governance.rollback import RollbackPlanGenerator
from backend.governance.state_machine import RemediationStateMachine
from backend.governance.verifier import IndependentPostActionVerifier


def initialize_proof_chain_tables(db_path: Optional[str] = None) -> None:
    """Initializes SQLite proof chain tables."""
    conn = get_connection(db_path)
    with conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS proof_chains (
            chain_id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            resource_arn TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            evidence_digest TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_version TEXT NOT NULL,
            rule_set_digest TEXT NOT NULL,
            risk_score REAL NOT NULL,
            risk_policy_version TEXT NOT NULL,
            remediation_plan_id TEXT NOT NULL,
            remediation_plan_digest TEXT NOT NULL,
            lifecycle_state TEXT NOT NULL,
            attack_path_id TEXT,
            approver_identity TEXT,
            approval_timestamp TEXT,
            approval_expires_at TEXT,
            pre_execution_revalidation_status TEXT,
            execution_status TEXT,
            post_verification_status TEXT,
            created_at TEXT NOT NULL,
            dossier_hash TEXT
        )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pc_finding ON proof_chains(finding_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pc_resource ON proof_chains(resource_arn)")
    conn.close()


class ProofChainService:
    """Orchestrates the 20-step Evidence-to-Action Proof Chain."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        initialize_proof_chain_tables(db_path)

    def create_investigation_chain(
        self,
        finding_id: str,
        resource_arn: str,
        evidence_id: str,
        evidence_digest: str,
        rule_id: str,
        rule_version: str,
        rule_set_digest: str,
        risk_score: float,
        risk_policy_version: str,
        remediation_action: str,
        parameters: Dict[str, Any],
        attack_path_id: Optional[str] = None,
        caller_role: str = "INVESTIGATOR"
    ) -> ProofChainRecord:
        """
        Steps 1–13: Ingestion, evidence binding, rule check, risk, and pending approval request creation.
        """
        chain_id = f"CHN-{uuid.uuid4().hex[:10]}"
        plan_id = f"PLAN-{uuid.uuid4().hex[:8]}"

        # Compute rollback plan
        rollback = RollbackPlanGenerator.generate_rollback(
            action_type=remediation_action,
            resource_arn=resource_arn,
            parameters=parameters
        )

        plan = RemediationPlan(
            plan_id=plan_id,
            finding_id=finding_id,
            resource_arn=resource_arn,
            action_type=remediation_action,
            parameters=parameters,
            preconditions={"required_evidence_digest": evidence_digest},
            rollback_plan=rollback
        )

        record = ProofChainRecord(
            chain_id=chain_id,
            finding_id=finding_id,
            resource_arn=resource_arn,
            evidence_id=evidence_id,
            evidence_digest=evidence_digest,
            rule_id=rule_id,
            rule_version=rule_version,
            rule_set_digest=rule_set_digest,
            risk_score=risk_score,
            risk_policy_version=risk_policy_version,
            remediation_plan_id=plan_id,
            remediation_plan_digest=plan.plan_digest,
            lifecycle_state=ProposalLifecycleState.PENDING,
            attack_path_id=attack_path_id
        )

        self._save_chain(record)

        try:
            from backend.audit import log_event
            log_event(
                "PROOF_CHAIN_INITIATED",
                {
                    "chain_id": chain_id,
                    "finding_id": finding_id,
                    "resource_arn": resource_arn,
                    "evidence_id": evidence_id,
                    "plan_digest": plan.plan_digest
                }
            )
        except Exception:
            pass

        return record

    def authorize_approval(
        self,
        chain_id: str,
        approver: str,
        caller_role: str,
        expires_at: str,
        session_id: Optional[str] = None
    ) -> ProofChainRecord:
        """
        Steps 14–15: Authenticated human authorization, role verification, and expiration binding.
        Enforces that approval can only occur from PENDING state and requires verified caller role.
        """
        record = self.get_chain(chain_id)
        if not record:
            raise ValueError(f"Proof chain '{chain_id}' not found.")

        # Finding 1 & 2: Check current state
        if record.lifecycle_state != ProposalLifecycleState.PENDING:
            raise ValueError(f"Invalid state transition: Cannot approve proof chain in state '{record.lifecycle_state.value}'. Must be PENDING.")

        # Finding 2: Enforce trusted session boundary if session_id is provided
        if session_id:
            from backend.session_store import valid_session, get_session
            if not valid_session(session_id):
                raise PermissionError("Authentication required: Invalid or expired approver session.")
            session_data = get_session(session_id)
            if session_data.get("username") != approver:
                raise PermissionError(f"Approver identity mismatch: Session user '{session_data.get('username')}' does not match requested approver '{approver}'.")

        # State transition check (enforces caller_role != ai_agent and caller_role in APPROVER, ADMINISTRATOR)
        RemediationStateMachine.transition(
            current_state=record.lifecycle_state,
            target_state=ProposalLifecycleState.APPROVED,
            caller_role=caller_role,
            expires_at=expires_at
        )

        now = datetime.now(timezone.utc).isoformat()
        record.lifecycle_state = ProposalLifecycleState.APPROVED
        record.approver_identity = approver
        record.approval_timestamp = now
        record.approval_expires_at = expires_at

        self._save_chain(record)

        try:
            from backend.audit import log_event
            log_event(
                "PROOF_CHAIN_APPROVED",
                {
                    "chain_id": chain_id,
                    "approver": approver,
                    "caller_role": caller_role,
                    "expires_at": expires_at,
                    "plan_digest": record.remediation_plan_digest
                }
            )
        except Exception:
            pass

        return record

    def execute_and_verify(
        self,
        chain_id: str,
        current_evidence_digest: str,
        post_execution_state: Optional[Dict[str, Any]] = None,
        caller_role: str = "ADMINISTRATOR"
    ) -> ProofChainRecord:
        """
        Steps 16–20: Pre-execution revalidation, simulated execution,
        independent post-action verification, audit emission, and dossier sealing.
        Enforces that execution requires current APPROVED state and verified ADMINISTRATOR role.
        """
        record = self.get_chain(chain_id)
        if not record:
            raise ValueError(f"Proof chain '{chain_id}' not found.")

        # Finding 1: Enforce current APPROVED state before execution
        if record.lifecycle_state != ProposalLifecycleState.APPROVED:
            raise PermissionError(
                f"Unauthorized Execution: Cannot execute proposal in state '{record.lifecycle_state.value}'. "
                f"Proposal must be in '{ProposalLifecycleState.APPROVED.value}' state before execution."
            )

        # Finding 1: Enforce caller_role authorization via State Machine and RBAC
        RemediationStateMachine.transition(
            current_state=record.lifecycle_state,
            target_state=ProposalLifecycleState.EXECUTING,
            caller_role=caller_role
        )

        # Step 15: Check expiration
        if record.approval_expires_at:
            clean = record.approval_expires_at.replace("Z", "+00:00")
            exp_dt = datetime.fromisoformat(clean)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp_dt:
                record.lifecycle_state = ProposalLifecycleState.EXPIRED
                self._save_chain(record)
                raise PermissionError(f"Approval expired at {record.approval_expires_at}.")

        # Step 16: Pre-execution revalidation (Scenario 2 / Scenario 4)
        if current_evidence_digest != record.evidence_digest:
            record.lifecycle_state = ProposalLifecycleState.INVALIDATED
            record.pre_execution_revalidation_status = "FAILED_EVIDENCE_MISMATCH"
            self._save_chain(record)
            try:
                from backend.audit import log_event
                log_event("PROOF_CHAIN_INVALIDATED", {"chain_id": chain_id, "reason": "Evidence payload digest changed prior to execution"})
            except Exception:
                pass
            raise ValueError("Pre-execution revalidation failed: Evidence hash mismatch. Approval invalidated.")

        record.pre_execution_revalidation_status = "PASSED"
        record.lifecycle_state = ProposalLifecycleState.EXECUTED
        record.execution_status = "SIMULATED_SUCCESS_ZERO_MUTATION"

        # Step 18: Independent post-action verification (Scenario 6)
        # Finding 3: If post_execution_state is None, verifier queries ground-truth directly
        action_type = "enable_s3_block_public_access" if "s3" in record.resource_arn else "revoke_security_group_ingress"
        is_verified, reason, details = IndependentPostActionVerifier.verify_remediation(
            resource_arn=record.resource_arn,
            action_type=action_type,
            post_execution_state=post_execution_state,
            db_path=self.db_path
        )

        if is_verified:
            record.lifecycle_state = ProposalLifecycleState.VERIFIED
            record.post_verification_status = "VERIFIED"
        else:
            record.lifecycle_state = ProposalLifecycleState.VERIFICATION_FAILED
            record.post_verification_status = f"FAILED: {reason}"

        # Step 20: Package cryptographic evidence dossier
        dossier_pkg = EvidenceDossierGenerator.generate_dossier(
            proof_chain_record=record.to_dict(),
            finding_details={"finding_id": record.finding_id, "resource_arn": record.resource_arn, "severity": "CRITICAL"},
            evidence_record={"evidence_id": record.evidence_id, "payload_sha256": record.evidence_digest, "integrity_status": "VERIFIED"},
            rule_evaluation={"rule_id": record.rule_id, "status": "FAIL", "violations": ["Public access active"]},
            risk_score_details={"overall_score": record.risk_score, "severity": "CRITICAL", "component_breakdown": {}},
            remediation_plan={"action_type": action_type, "plan_digest": record.remediation_plan_digest, "rollback_plan": {}},
            verification_report={"status": record.post_verification_status, "reason": reason}
        )
        record.dossier_hash = dossier_pkg["dossier_root_hash"]

        self._save_chain(record)

        try:
            from backend.audit import log_event
            log_event(
                "PROOF_CHAIN_COMPLETED",
                {
                    "chain_id": chain_id,
                    "lifecycle_state": record.lifecycle_state.value,
                    "post_verification_status": record.post_verification_status,
                    "dossier_hash": record.dossier_hash
                }
            )
        except Exception:
            pass

        return record

    def get_chain(self, chain_id: str) -> Optional[ProofChainRecord]:
        """Retrieves a proof chain by ID."""
        conn = get_connection(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM proof_chains WHERE chain_id = ?", (chain_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_record(row)
        finally:
            conn.close()

    def list_chains(self, resource_arn: Optional[str] = None, state: Optional[str] = None) -> List[ProofChainRecord]:
        """Lists proof chains."""
        conn = get_connection(self.db_path)
        try:
            cursor = conn.cursor()
            query = "SELECT * FROM proof_chains WHERE 1=1"
            params = []
            if resource_arn:
                query += " AND resource_arn = ?"
                params.append(resource_arn)
            if state:
                query += " AND lifecycle_state = ?"
                params.append(state.upper())
            query += " ORDER BY created_at DESC"
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [self._row_to_record(r) for r in rows]
        finally:
            conn.close()

    def _save_chain(self, record: ProofChainRecord) -> None:
        conn = get_connection(self.db_path)
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO proof_chains (
                        chain_id, finding_id, resource_arn, evidence_id, evidence_digest,
                        rule_id, rule_version, rule_set_digest, risk_score, risk_policy_version,
                        remediation_plan_id, remediation_plan_digest, lifecycle_state,
                        attack_path_id, approver_identity, approval_timestamp, approval_expires_at,
                        pre_execution_revalidation_status, execution_status, post_verification_status,
                        created_at, dossier_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(chain_id) DO UPDATE SET
                        lifecycle_state = excluded.lifecycle_state,
                        approver_identity = excluded.approver_identity,
                        approval_timestamp = excluded.approval_timestamp,
                        approval_expires_at = excluded.approval_expires_at,
                        pre_execution_revalidation_status = excluded.pre_execution_revalidation_status,
                        execution_status = excluded.execution_status,
                        post_verification_status = excluded.post_verification_status,
                        dossier_hash = excluded.dossier_hash
                    """,
                    (
                        record.chain_id,
                        record.finding_id,
                        record.resource_arn,
                        record.evidence_id,
                        record.evidence_digest,
                        record.rule_id,
                        record.rule_version,
                        record.rule_set_digest,
                        record.risk_score,
                        record.risk_policy_version,
                        record.remediation_plan_id,
                        record.remediation_plan_digest,
                        record.lifecycle_state.value,
                        record.attack_path_id,
                        record.approver_identity,
                        record.approval_timestamp,
                        record.approval_expires_at,
                        record.pre_execution_revalidation_status,
                        record.execution_status,
                        record.post_verification_status,
                        record.created_at,
                        record.dossier_hash
                    )
                )
        finally:
            conn.close()

    def _row_to_record(self, row: Any) -> ProofChainRecord:
        return ProofChainRecord(
            chain_id=row[0],
            finding_id=row[1],
            resource_arn=row[2],
            evidence_id=row[3],
            evidence_digest=row[4],
            rule_id=row[5],
            rule_version=row[6],
            rule_set_digest=row[7],
            risk_score=row[8],
            risk_policy_version=row[9],
            remediation_plan_id=row[10],
            remediation_plan_digest=row[11],
            lifecycle_state=ProposalLifecycleState(row[12]),
            attack_path_id=row[13],
            approver_identity=row[14],
            approval_timestamp=row[15],
            approval_expires_at=row[16],
            pre_execution_revalidation_status=row[17],
            execution_status=row[18],
            post_verification_status=row[19],
            created_at=row[20],
            dossier_hash=row[21]
        )
