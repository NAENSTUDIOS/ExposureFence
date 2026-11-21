"""
ExposureFence — Autonomous Problem Classifier
Classifies security problems by domain, severity, and confidence, while
distinguishing superficial symptoms from underlying root causes.
"""

import uuid

from backend.adaptive.models import ChangeEvent, ImpactReport, ProblemClassification


class ProblemClassifier:
    """Classifies problems to feed the Autonomous Solution Engine."""

    @staticmethod
    def classify(event: ChangeEvent, impact: ImpactReport) -> ProblemClassification:
        problem_id = f"PRB-{uuid.uuid4().hex[:8]}"
        desc_l = event.description.lower()

        # Domain classification
        if "iam" in desc_l or "passrole" in desc_l:
            domain = "IAM_PERMISSIONS"
            root_cause = "Outdated IAM attack path traversal heuristics lacking modern multi-service PassRole combinations."
        elif "s3" in desc_l or "object lock" in desc_l:
            domain = "CLOUD_INFRA"
            root_cause = "Compliance policy drift: S3 inspection rules lack Object Lock validation attributes."
        elif "cve" in desc_l or "imdsv1" in desc_l:
            domain = "CLOUD_INFRA"
            root_cause = "Vulnerability exposure: EC2 instances permitting legacy unauthenticated IMDSv1 calls."
        elif "prompt" in desc_l or "injection" in desc_l:
            domain = "AI_AGENT"
            root_cause = "Adversarial technique evolution: Resource metadata tags used as indirect prompt injection vectors."
        elif "drift" in desc_l or "health" in desc_l:
            domain = "PLATFORM_HEALTH"
            root_cause = "Internal index discrepancy: Secondary search cache out of sync with verified SQLite state."
        else:
            domain = "COMPLIANCE"
            root_cause = "Regulatory baseline divergence."

        symptoms = [
            f"Observed event: {event.title}",
            f"Impacted components: {', '.join(impact.affected_components[:3])}"
        ]

        return ProblemClassification(
            problem_id=problem_id,
            event_id=event.event_id,
            domain=domain,
            severity=event.urgency,
            confidence=event.confidence,
            root_cause_hypothesis=root_cause,
            symptoms=symptoms,
            affected_components=impact.affected_components
        )
