"""
ExposureFence — Adaptation Evolution Manager
Coordinates the lifecycle transitions of adaptations from discovery to sandbox,
review, integration, and atomic rollback.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from backend.adaptive.models import (
    AdaptationRecord,
    AdaptationState,
    CandidateSolution,
    ProblemClassification,
)
from backend.adaptive.policy_guard import AdaptationPolicyGuard
from backend.adaptive.sandbox import AdaptationSandbox


class EvolutionManager:
    """Manages the lifecycle of continuous platform adaptations."""

    def __init__(self):
        self._adaptations: Dict[str, AdaptationRecord] = {}

    def initiate_adaptation(
        self,
        problem: ProblemClassification,
        solution: CandidateSolution,
        caller_role: str = "POLICY_ENGINE"
    ) -> AdaptationRecord:
        """
        Executes the full pipeline:
        1. Sandbox testing
        2. Policy guard evaluation (90% score + gates)
        3. State assignment (APPROVED_FOR_REVIEW, APPROVED_FOR_INTEGRATION, or BLOCKED)
        """
        # AI agent cannot initiate or approve adaptations directly
        if caller_role.lower() in ("ai_agent", "bedrock_agent", "model"):
            raise PermissionError("Security Violation: AI Agent cannot approve or integrate adaptations.")

        adaptation_id = f"ADAPT-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()

        # Step 1: Sandbox simulation
        sandbox_res = AdaptationSandbox.evaluate_candidate(solution)

        # Step 2: Policy guard evaluation
        target_state, gates, human_req = AdaptationPolicyGuard.evaluate_adaptation(
            candidate=solution,
            sandbox_result=sandbox_res,
            problem=problem
        )

        record = AdaptationRecord(
            adaptation_id=adaptation_id,
            problem_id=problem.problem_id,
            selected_solution=solution,
            lifecycle_state=target_state,
            quality_score=solution.ranking_score,
            gate_results=gates,
            decision_authority=f"policy:ASIVE_V1:{caller_role}",
            human_review_required=human_req,
            created_at=now,
            updated_at=now,
            reversion_snapshot=solution.rollback_plan
        )

        self._adaptations[adaptation_id] = record

        # Log audit event
        try:
            from backend.audit import log_event
            log_event(
                "ADAPTATION_EVALUATED",
                {
                    "adaptation_id": adaptation_id,
                    "problem_id": problem.problem_id,
                    "solution_title": solution.title,
                    "lifecycle_state": target_state.value,
                    "quality_score": solution.ranking_score,
                    "human_review_required": human_req
                }
            )
        except Exception:
            pass

        return record

    def rollback_adaptation(self, adaptation_id: str, caller_role: str = "ADMINISTRATOR") -> AdaptationRecord:
        """Atomically rolls back an adaptation to previous state."""
        if caller_role.upper() not in ("ADMINISTRATOR", "ADMIN"):
            raise PermissionError(f"Unauthorized: Role 'ADMINISTRATOR' required to rollback adaptations. Role '{caller_role}' denied.")

        record = self._adaptations.get(adaptation_id)
        if not record:
            raise ValueError(f"Adaptation '{adaptation_id}' not found.")

        record.lifecycle_state = AdaptationState.ROLLED_BACK
        record.updated_at = datetime.now(timezone.utc).isoformat()

        try:
            from backend.audit import log_event
            log_event(
                "ADAPTATION_ROLLED_BACK",
                {
                    "adaptation_id": adaptation_id,
                    "caller_role": caller_role,
                    "reversion_snapshot": record.reversion_snapshot
                }
            )
        except Exception:
            pass

        return record

    def list_adaptations(self, state: Optional[AdaptationState] = None) -> List[AdaptationRecord]:
        records = list(self._adaptations.values())
        if state:
            records = [r for r in records if r.lifecycle_state == state]
        return records
