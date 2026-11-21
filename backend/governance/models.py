"""
ExposureFence — Governance & Proof Chain Models
Defines the 14 proposal lifecycle states, remediation plans, rollback specifications,
and complete 20-step evidence-to-action proof chain records.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional


class ProposalLifecycleState(str, Enum):
    DRAFT = "DRAFT"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    AUTO_APPROVED_CONDITIONAL = "AUTO_APPROVED_CONDITIONAL"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    INVALIDATED = "INVALIDATED"
    READY_FOR_EXECUTION = "READY_FOR_EXECUTION"
    EXECUTING = "EXECUTING"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    EXECUTED = "EXECUTED"
    VERIFICATION_PENDING = "VERIFICATION_PENDING"
    VERIFIED = "VERIFIED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"


@dataclass
class RemediationPlan:
    plan_id: str
    finding_id: str
    resource_arn: str
    action_type: str
    parameters: Dict[str, Any]
    preconditions: Dict[str, Any]
    rollback_plan: Dict[str, Any]
    plan_digest: str = ""

    def __post_init__(self):
        if not self.plan_digest:
            canonical_repr = {
                "action_type": self.action_type,
                "parameters": self.parameters,
                "preconditions": self.preconditions,
                "resource_arn": self.resource_arn
            }
            encoded = json.dumps(canonical_repr, sort_keys=True).encode("utf-8")
            self.plan_digest = hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProofChainRecord:
    chain_id: str
    finding_id: str
    resource_arn: str
    evidence_id: str
    evidence_digest: str
    rule_id: str
    rule_version: str
    rule_set_digest: str
    risk_score: float
    risk_policy_version: str
    remediation_plan_id: str
    remediation_plan_digest: str
    lifecycle_state: ProposalLifecycleState = ProposalLifecycleState.PENDING
    attack_path_id: Optional[str] = None
    approver_identity: Optional[str] = None
    approval_timestamp: Optional[str] = None
    approval_expires_at: Optional[str] = None
    pre_execution_revalidation_status: Optional[str] = None
    execution_status: Optional[str] = None
    post_verification_status: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    dossier_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["lifecycle_state"] = self.lifecycle_state.value if isinstance(self.lifecycle_state, ProposalLifecycleState) else str(self.lifecycle_state)
        return d
