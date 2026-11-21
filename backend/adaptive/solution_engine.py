"""
ExposureFence — Autonomous Solution Engine & Deterministic Ranker
Discovers, formulates, and ranks multiple candidate solutions for classified problems.
Ranks solutions deterministically across 10 dimensions with structured explanations.
"""

from typing import Any, Dict, List, Tuple
import uuid

from backend.adaptive.models import CandidateSolution, ProblemClassification


class SolutionEngine:
    """
    Generates multiple candidate solutions for a security problem, evaluating each
    against safety, reversibility, testability, and regression risk.
    """

    @classmethod
    def generate_candidate_solutions(cls, problem: ProblemClassification) -> List[CandidateSolution]:
        candidates: List[CandidateSolution] = []

        if problem.domain == "IAM_PERMISSIONS":
            # Candidate 1: Rule update (Primary)
            c1 = cls._build_candidate(
                problem=problem,
                title="Extend IAM Privilege Escalation Heuristics (ESC-07: PassRole + Glue)",
                solution_type="RULE_UPDATE",
                changes={"rule_id": "R03", "add_pattern": "iam:PassRole->glue:CreateDevEndpoint", "reversibility": "HIGH"},
                explanation="Adds formal graph edge check for indirect Glue PassRole escalation to protect against unauthorized lateral movement.",
                risks=["Slight increase in graph traversal branch factor."],
                rollback={"remove_pattern": "iam:PassRole->glue:CreateDevEndpoint"},
                required_tests=["tests/offline/test_redteam_graph.py::test_iam_privilege_escalation_detection_multi_hop"]
            )
            candidates.append(c1)

            # Candidate 2: Policy guard alert (Alternative)
            c2 = cls._build_candidate(
                problem=problem,
                title="Add Advisory Warning to High-Risk PassRole Findings",
                solution_type="RISK_ADJUSTMENT",
                changes={"risk_factor": "glue_passrole", "multiplier": 1.25},
                explanation="Increases contextual risk score when PassRole permissions are detected on developer roles.",
                risks=["Does not directly block attack path traversal."],
                rollback={"reset_multiplier": 1.0},
                required_tests=["tests/offline/test_offline_suite.py"]
            )
            candidates.append(c2)

        elif problem.domain == "AI_AGENT":
            # Candidate 1: Tag sanitization filter
            c1 = cls._build_candidate(
                problem=problem,
                title="Enhance Indirect Metadata Tag Invariant Sanitizer (R06/R07)",
                solution_type="RULE_UPDATE",
                changes={"rules": ["R06", "R07"], "sanitize_keys": ["Description", "Owner", "Comment"]},
                explanation="Strips control characters, prompt jailbreak phrases, and system directives from incoming resource tags.",
                risks=["May truncate long legitimate resource descriptions."],
                rollback={"restore_rules": "rules/rules.yaml.bak"},
                required_tests=["tests/offline/test_redteam_agent.py::test_agent_direct_prompt_injection_containment"]
            )
            candidates.append(c1)

        elif problem.domain == "PLATFORM_HEALTH":
            # Candidate 1: Safe self-healing local cache rebuild
            c1 = cls._build_candidate(
                problem=problem,
                title="Rebuild Local Search Cache and Resync Secondary Index",
                solution_type="SELF_HEAL",
                changes={"action": "REBUILD_LOCAL_INDEX", "target": "search_cache"},
                explanation="Safely flushes and recomputes the secondary in-memory asset index from verified SQLite database.",
                risks=["Temporary read latency spike during index regeneration."],
                rollback={"restore_previous_cache": True},
                required_tests=["tests/offline/test_redteam_operational.py"]
            )
            candidates.append(c1)

        else:
            # Generic candidate
            c1 = cls._build_candidate(
                problem=problem,
                title=f"Update Detection Rule Baseline for {problem.domain}",
                solution_type="RULE_UPDATE",
                changes={"domain": problem.domain, "baseline_update": True},
                explanation="Updates declarative rules baseline to track emerging framework specifications.",
                risks=["Requires manual verification of compliance tags."],
                rollback={"revert_baseline": True},
                required_tests=["tests/offline/test_attack_suite.py"]
            )
            candidates.append(c1)

        # Rank candidates deterministically
        for c in candidates:
            score, breakdown = cls._rank_candidate(c, problem)
            c.ranking_score = score
            c.score_breakdown = breakdown

        candidates.sort(key=lambda x: x.ranking_score, reverse=True)
        return candidates

    @classmethod
    def _build_candidate(
        cls,
        problem: ProblemClassification,
        title: str,
        solution_type: str,
        changes: Dict[str, Any],
        explanation: str,
        risks: List[str],
        rollback: Dict[str, Any],
        required_tests: List[str]
    ) -> CandidateSolution:
        return CandidateSolution(
            solution_id=f"SOL-{uuid.uuid4().hex[:8]}",
            problem_id=problem.problem_id,
            title=title,
            solution_type=solution_type,
            proposed_changes=changes,
            ranking_score=0.0,
            score_breakdown={},
            explanation=explanation,
            risks=risks,
            rollback_plan=rollback,
            required_tests=required_tests
        )

    @staticmethod
    def _rank_candidate(candidate: CandidateSolution, problem: ProblemClassification) -> Tuple[float, Dict[str, float]]:
        """
        Ranks candidate solutions across 10 dimensions (100 points maximum):
        1. Security effectiveness (15)
        2. Evidence quality (12)
        3. Compatibility (12)
        4. Regression risk (12)
        5. Reversibility (10)
        6. Operational cost (10)
        7. Complexity (10)
        8. Maintainability (10)
        9. Confidence (10)
        10. Underlying problem coverage (9)
        """
        b = {}
        # Security effectiveness
        b["security_effectiveness"] = 14.0 if candidate.solution_type in ("RULE_UPDATE", "SELF_HEAL") else 10.0
        # Evidence quality
        b["evidence_quality"] = 11.0 if problem.confidence >= 0.90 else 8.0
        # Compatibility (zero breaking changes)
        b["compatibility"] = 11.5
        # Regression risk (low risk gives higher score)
        b["regression_risk"] = 11.0 if len(candidate.risks) <= 1 else 8.0
        # Reversibility (presence of rollback plan)
        b["reversibility"] = 9.5 if candidate.rollback_plan else 4.0
        # Operational cost (zero cloud cost = 10.0)
        b["operational_cost"] = 10.0
        # Complexity (manageable changes = higher score)
        b["complexity"] = 9.0
        # Maintainability
        b["maintainability"] = 9.0
        # Confidence
        b["confidence"] = round(problem.confidence * 10.0, 1)
        # Problem coverage
        b["problem_coverage"] = 8.5

        total = round(sum(b.values()), 2)
        return total, b
