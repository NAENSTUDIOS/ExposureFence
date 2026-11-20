"""
ExposureFence — Proposal Lifecycle State Machine
Enforces deterministic 14-state proposal transitions, role-based authorization,
time-to-live expiration validation, and pre-execution invalidation.
"""

from datetime import datetime, timezone
from typing import Dict, Optional, Set

from backend.governance.models import ProposalLifecycleState


# Explicit allowed transitions table
ALLOWED_TRANSITIONS: Dict[ProposalLifecycleState, Set[ProposalLifecycleState]] = {
    ProposalLifecycleState.DRAFT: {ProposalLifecycleState.PENDING},
    ProposalLifecycleState.PENDING: {
        ProposalLifecycleState.APPROVED,
        ProposalLifecycleState.REJECTED,
        ProposalLifecycleState.EXPIRED
    },
    ProposalLifecycleState.APPROVED: {
        ProposalLifecycleState.READY_FOR_EXECUTION,
        ProposalLifecycleState.EXECUTING,
        ProposalLifecycleState.REVOKED,
        ProposalLifecycleState.INVALIDATED,
        ProposalLifecycleState.EXPIRED
    },
    ProposalLifecycleState.READY_FOR_EXECUTION: {
        ProposalLifecycleState.EXECUTING,
        ProposalLifecycleState.INVALIDATED
    },
    ProposalLifecycleState.EXECUTING: {
        ProposalLifecycleState.EXECUTED,
        ProposalLifecycleState.EXECUTION_FAILED
    },
    ProposalLifecycleState.EXECUTED: {
        ProposalLifecycleState.VERIFICATION_PENDING,
        ProposalLifecycleState.VERIFIED,
        ProposalLifecycleState.VERIFICATION_FAILED
    },
    ProposalLifecycleState.VERIFICATION_PENDING: {
        ProposalLifecycleState.VERIFIED,
        ProposalLifecycleState.VERIFICATION_FAILED
    },
    # Terminal or inactive states
    ProposalLifecycleState.REJECTED: set(),
    ProposalLifecycleState.EXPIRED: set(),
    ProposalLifecycleState.REVOKED: set(),
    ProposalLifecycleState.INVALIDATED: set(),
    ProposalLifecycleState.EXECUTION_FAILED: {ProposalLifecycleState.READY_FOR_EXECUTION},
    ProposalLifecycleState.VERIFIED: set(),
    ProposalLifecycleState.VERIFICATION_FAILED: {ProposalLifecycleState.READY_FOR_EXECUTION}
}


class RemediationStateMachine:
    """Enforces state transition rules and role boundaries across the 14 proposal states."""

    @staticmethod
    def transition(
        current_state: ProposalLifecycleState,
        target_state: ProposalLifecycleState,
        caller_role: str,
        expires_at: Optional[str] = None
    ) -> ProposalLifecycleState:
        """
        Validates and executes a state transition.
        """
        # AI caller cannot approve or execute
        if caller_role.lower() in ("ai_agent", "bedrock_agent", "model"):
            if target_state not in (ProposalLifecycleState.DRAFT, ProposalLifecycleState.PENDING):
                raise PermissionError("Security Violation: AI Agent cannot approve or execute proposals.")

        # Check allowed transitions
        allowed = ALLOWED_TRANSITIONS.get(current_state, set())
        if target_state not in allowed:
            raise ValueError(f"Invalid state transition: Cannot transition from {current_state.value} to {target_state.value}.")

        # Check expiration for approval and execution
        if target_state in (ProposalLifecycleState.APPROVED, ProposalLifecycleState.READY_FOR_EXECUTION):
            if expires_at:
                try:
                    clean = expires_at.replace("Z", "+00:00")
                    exp_dt = datetime.fromisoformat(clean)
                    if exp_dt.tzinfo is None:
                        exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    if now > exp_dt:
                        raise PermissionError(f"Proposal expired at {expires_at}; cannot transition to {target_state.value}.")
                except ValueError:
                    pass

        # Role checks
        if target_state == ProposalLifecycleState.APPROVED:
            if caller_role.upper() not in ("APPROVER", "ADMINISTRATOR", "ADMIN"):
                raise PermissionError("Unauthorized: Role 'APPROVER' or 'ADMINISTRATOR' required to approve proposals.")

        if target_state in (ProposalLifecycleState.READY_FOR_EXECUTION, ProposalLifecycleState.EXECUTING, ProposalLifecycleState.EXECUTED):
            if caller_role.upper() not in ("ADMINISTRATOR", "ADMIN"):
                raise PermissionError(f"Unauthorized: Role 'ADMINISTRATOR' required to execute remediation. Role '{caller_role}' denied.")

        return target_state
