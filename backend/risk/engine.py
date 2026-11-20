"""
ExposureFence — Contextual Risk Engine Service
Computes deterministic multi-factor contextual risk scores, enforces versioned policies,
and checks active risk acceptances.
"""

from typing import List, Optional

from backend.graph.models import AttackPath, BlastRadiusResult
from backend.intelligence.models import AssetRecord, CanonicalFinding
from backend.risk.acceptance import RiskAcceptanceService
from backend.risk.models import RiskScore
from backend.risk.policies import RiskPolicyV1, RiskPolicyV2


class ContextualRiskEngine:
    """
    Deterministic risk calculation engine combining finding metadata, asset context,
    attack path discovery, blast radius, evidence integrity, and freshness.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        self.acceptance_service = RiskAcceptanceService(db_path=db_path)

    def calculate_risk(
        self,
        finding: CanonicalFinding,
        asset: Optional[AssetRecord] = None,
        evidence: Optional[Any] = None,
        attack_paths: Optional[List[AttackPath]] = None,
        blast_radius: Optional[BlastRadiusResult] = None,
        policy_version: str = "2.0.0"
    ) -> RiskScore:
        """
        Calculates an authoritative, deterministic contextual risk score.
        """
        evidence_ids = []
        if finding.evidence_id:
            evidence_ids.append(finding.evidence_id)
        if evidence and hasattr(evidence, "evidence_id"):
            evidence_ids.append(evidence.evidence_id)

        # Check legacy Policy V1 fallback
        if policy_version == "1.0.0":
            score, severity, breakdown = RiskPolicyV1.evaluate(finding.title)
            active_acc = self.acceptance_service.get_active_acceptance(
                finding_id=finding.finding_id,
                resource_arn=finding.resource_arn
            )
            is_acc = active_acc is not None
            return RiskScore(
                overall_score=score,
                severity=severity,
                scoring_policy_version="1.0.0",
                component_breakdown=breakdown,
                input_evidence_ids=evidence_ids,
                is_accepted=is_acc,
                effective_score=0.0 if is_acc else score
            )

        # Multi-factor evaluation (Policy V2)
        criticality = 50.0
        if asset:
            tags = asset.tags or {}
            env = tags.get("Environment", "").lower()
            if "prod" in env or "finance" in tags.get("Department", "").lower():
                criticality = 90.0
        if "finance" in finding.resource_arn or "audit" in finding.resource_arn:
            criticality = 100.0

        # Exposure factor
        exposure = 0.0
        if "public" in finding.title.lower() or "0.0.0.0/0" in finding.description or "::/0" in finding.description:
            exposure = 100.0
        elif finding.severity.value in ("CRITICAL", "HIGH"):
            exposure = 75.0

        # Reachability factor from graph attack paths
        reachability = 0.0
        if attack_paths:
            # If any path exists and has high confidence
            max_path_risk = max((p.risk_score for p in attack_paths), default=0.0)
            reachability = max_path_risk
        elif exposure > 0:
            reachability = 50.0

        # IAM privilege factor
        iam_privilege = 0.0
        if "AdministratorAccess" in finding.title or "AdministratorAccess" in finding.description:
            iam_privilege = 100.0
        elif attack_paths and any(any("Admin" in nid or "policy" in nid.lower() for nid in p.intermediate_node_ids) for p in attack_paths):
            iam_privilege = 90.0
        elif "iam" in finding.service:
            iam_privilege = 70.0

        # Blast radius
        blast_score = 0.0
        if blast_radius:
            blast_score = blast_radius.cumulative_risk_impact
        elif attack_paths and len(attack_paths) > 0:
            blast_score = 60.0

        # Evidence integrity and freshness
        integrity_status = "VERIFIED"
        freshness_status = "FRESH"
        if evidence:
            integrity_status = getattr(evidence, "integrity_status", "VERIFIED")
            freshness_status = getattr(evidence, "freshness_status", "FRESH")

        score, severity, breakdown = RiskPolicyV2.evaluate(
            criticality=criticality,
            exposure=exposure,
            reachability=reachability,
            iam_privilege=iam_privilege,
            blast_radius=blast_score,
            integrity_status=integrity_status,
            freshness_status=freshness_status
        )

        active_acceptance = self.acceptance_service.get_active_acceptance(
            finding_id=finding.finding_id,
            resource_arn=finding.resource_arn
        )
        is_accepted = active_acceptance is not None

        return RiskScore(
            overall_score=score,
            severity=severity,
            scoring_policy_version=RiskPolicyV2.VERSION,
            component_breakdown=breakdown,
            input_evidence_ids=evidence_ids,
            is_accepted=is_accepted,
            effective_score=0.0 if is_accepted else score
        )
