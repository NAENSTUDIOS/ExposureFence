"""
ExposureFence — ASIVE Data Models & Provider-Neutral Abstractions
Supports multi-cloud extensibility (AWS, Azure, GCP, Kubernetes) with
unified schemas for observations, change events, impact reports, candidate solutions,
adaptation lifecycles, and versioned security knowledge.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional


class CloudProvider(str, Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    KUBERNETES = "KUBERNETES"
    MULTI_CLOUD = "MULTI_CLOUD"


class ObservationSourceType(str, Enum):
    CLOUD_SECURITY = "CLOUD_SECURITY"
    VULNERABILITY = "VULNERABILITY"
    AI_SECURITY = "AI_SECURITY"
    COMPLIANCE = "COMPLIANCE"
    PROJECT_HEALTH = "PROJECT_HEALTH"


class ChangeEventCategory(str, Enum):
    NEW_THREAT = "NEW_THREAT"
    NEW_VULNERABILITY = "NEW_VULNERABILITY"
    AWS_SERVICE_CHANGE = "AWS_SERVICE_CHANGE"
    AWS_API_CHANGE = "AWS_API_CHANGE"
    SECURITY_CONTROL_CHANGE = "SECURITY_CONTROL_CHANGE"
    COMPLIANCE_CHANGE = "COMPLIANCE_CHANGE"
    DEPENDENCY_VULNERABILITY = "DEPENDENCY_VULNERABILITY"
    ATTACK_TECHNIQUE_CHANGE = "ATTACK_TECHNIQUE_CHANGE"
    CONNECTOR_FAILURE = "CONNECTOR_FAILURE"
    RULE_DEPRECATION = "RULE_DEPRECATION"
    POLICY_CONFLICT = "POLICY_CONFLICT"
    SECURITY_REGRESSION = "SECURITY_REGRESSION"
    PERFORMANCE_DEGRADATION = "PERFORMANCE_DEGRADATION"
    DOCUMENTATION_DRIFT = "DOCUMENTATION_DRIFT"


class ChangeEventStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    SUSPECTED = "SUSPECTED"
    UNVERIFIED = "UNVERIFIED"
    SUPERSEDED = "SUPERSEDED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class AdaptationState(str, Enum):
    DETECTED = "DETECTED"
    CLASSIFIED = "CLASSIFIED"
    INVESTIGATING = "INVESTIGATING"
    SOLUTION_PROPOSED = "SOLUTION_PROPOSED"
    EVALUATION_PENDING = "EVALUATION_PENDING"
    SANDBOX_TESTING = "SANDBOX_TESTING"
    VERIFICATION_PENDING = "VERIFICATION_PENDING"
    APPROVED_FOR_REVIEW = "APPROVED_FOR_REVIEW"
    APPROVED_FOR_INTEGRATION = "APPROVED_FOR_INTEGRATION"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"
    ROLLED_BACK = "ROLLED_BACK"
    RESOLVED = "RESOLVED"


@dataclass
class ObservationRecord:
    id: str
    source_type: ObservationSourceType
    source_name: str
    timestamp: str
    source_version: str
    evidence_ref: str
    payload: Dict[str, Any]
    integrity_hash: str = ""
    confidence: float = 1.0
    relevance: float = 1.0
    freshness: str = "FRESH"
    validation_status: str = "VALIDATED"
    provider: CloudProvider = CloudProvider.AWS

    def __post_init__(self):
        if not self.integrity_hash:
            encoded = json.dumps(self.payload, sort_keys=True).encode("utf-8")
            self.integrity_hash = hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ChangeEvent:
    event_id: str
    category: ChangeEventCategory
    title: str
    description: str
    detected_at: str
    status: ChangeEventStatus
    source_observation_ids: List[str]
    confidence: float
    urgency: str  # CRITICAL, HIGH, MEDIUM, LOW
    affected_components: List[str]
    provider: CloudProvider = CloudProvider.AWS
    dedup_fingerprint: str = ""

    def __post_init__(self):
        if not self.dedup_fingerprint:
            raw = f"{self.category.value}:{self.title.lower().strip()}:{self.provider.value}"
            self.dedup_fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ImpactReport:
    report_id: str
    event_id: str
    what_changed: str
    why_it_matters: str
    affected_components: List[str]
    outdated_controls: List[str]
    test_updates_needed: List[str]
    potential_security_impact: str
    urgency: str
    supporting_evidence: List[str]
    uncertainties: List[str]
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProblemClassification:
    problem_id: str
    event_id: str
    domain: str  # CLOUD_INFRA, IAM_PERMISSIONS, AI_AGENT, COMPLIANCE, PLATFORM_HEALTH
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float
    root_cause_hypothesis: str
    symptoms: List[str]
    affected_components: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CandidateSolution:
    solution_id: str
    problem_id: str
    title: str
    solution_type: str  # RULE_UPDATE, CONNECTOR_PATCH, TEST_EXPANSION, RISK_ADJUSTMENT, SELF_HEAL
    proposed_changes: Dict[str, Any]
    ranking_score: float
    score_breakdown: Dict[str, float]
    explanation: str
    risks: List[str]
    rollback_plan: Dict[str, Any]
    required_tests: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AdaptationRecord:
    adaptation_id: str
    problem_id: str
    selected_solution: CandidateSolution
    lifecycle_state: AdaptationState
    quality_score: float
    gate_results: List[Dict[str, Any]]
    decision_authority: str
    human_review_required: bool
    created_at: str
    updated_at: str
    reversion_snapshot: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class KnowledgeRecord:
    knowledge_id: str
    version: str
    title: str
    domain: str
    source_id: str
    effective_date: str
    review_date: str
    confidence: float
    evidence_hash: str
    affected_controls: List[str]
    adoption_status: str  # ADOPTED, CANDIDATE, SUPERSEDED, RETIRED

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FeedbackRecord:
    feedback_id: str
    solution_id: str
    outcome: str  # SUCCESS, REGRESSION, FALSE_POSITIVE, REJECTED_BY_REVIEWER
    human_notes: str
    false_positive: bool
    regression_observed: bool
    recorded_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
