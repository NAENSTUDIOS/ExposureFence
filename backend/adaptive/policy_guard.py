"""
ExposureFence — Verified Adaptation Policy Guard
Enforces the 90% threshold quality gate and mandatory security gates for ASIVE adaptations.
Mandates independent human review for all sensitive security changes (rules, governance, IAM).
Strictly prevents AI agent self-approval.
"""

from typing import Any, Dict, List, Tuple

from backend.adaptive.models import AdaptationState, CandidateSolution, ProblemClassification


class AdaptationPolicyGuard:
    """
    Enforces governance boundaries for candidate platform adaptations.
    """

    MINIMUM_ADAPTATION_SCORE = 90.0

    @classmethod
    def evaluate_adaptation(
        cls,
        candidate: CandidateSolution,
        sandbox_result: Dict[str, Any],
        problem: ProblemClassification
    ) -> Tuple[AdaptationState, List[Dict[str, Any]], bool]:
        """
        Evaluates a candidate solution against the adaptation policy.
        Returns: (TargetState, GateResults, HumanReviewRequired)
        """
        gates = []
        score = candidate.ranking_score
        all_passed = True

        # Gate 1: Sandbox Validation
        if not sandbox_result.get("sandbox_passed", False):
            gates.append({"gate": "SANDBOX_VERIFICATION", "passed": False, "reason": "Sandbox simulation failed."})
            all_passed = False
        else:
            gates.append({"gate": "SANDBOX_VERIFICATION", "passed": True, "reason": "Sandbox checks passed."})

        # Gate 2: Invariant Check (R01–R07)
        if not sandbox_result.get("invariants_intact", True):
            gates.append({"gate": "INVARIANT_PRESERVATION", "passed": False, "reason": "Security invariant violation."})
            all_passed = False
        else:
            gates.append({"gate": "INVARIANT_PRESERVATION", "passed": True, "reason": "Invariants preserved."})

        # Gate 3: Regression Detection
        if sandbox_result.get("regressions_detected", 0) > 0:
            gates.append({"gate": "ZERO_REGRESSIONS", "passed": False, "reason": "Regressions detected."})
            all_passed = False
        else:
            gates.append({"gate": "ZERO_REGRESSIONS", "passed": True, "reason": "Zero regressions verified."})

        # Gate 4: 90% Quality Score Threshold
        passed_score = score >= cls.MINIMUM_ADAPTATION_SCORE
        if not passed_score:
            gates.append({"gate": "QUALITY_SCORE_90_PCT", "passed": False, "reason": f"Score {score} < {cls.MINIMUM_ADAPTATION_SCORE}."})
            all_passed = False
        else:
            gates.append({"gate": "QUALITY_SCORE_90_PCT", "passed": True, "reason": f"Quality score {score} >= 90.0."})

        # Sensitive category check: All rule modifications, IAM heuristics, and governance require human review
        human_review_required = candidate.solution_type in ("RULE_UPDATE", "RISK_ADJUSTMENT") or problem.domain in ("IAM_PERMISSIONS", "AI_AGENT")

        if not all_passed:
            state = AdaptationState.BLOCKED
        elif human_review_required:
            state = AdaptationState.APPROVED_FOR_REVIEW
        else:
            # Safe local platform maintenance (e.g., self-healing local cache) can be approved for integration
            state = AdaptationState.APPROVED_FOR_INTEGRATION

        return state, gates, human_review_required
