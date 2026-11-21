"""
ExposureFence — Impact Analysis Engine
Determines exact dependencies affected by a detected change event across cloud services,
connectors, YAML rules, compliance frameworks, attack path algorithms, and tests.
Produces structured 9-point impact reports.
"""

from datetime import datetime, timezone
import uuid

from backend.adaptive.models import ChangeEvent, ImpactReport


class ImpactAnalyzer:
    """
    Evaluates how detected changes ripple through the ExposureFence architecture.
    Builds relationships and generates actionable 9-point impact reports.
    """

    @staticmethod
    def analyze_impact(event: ChangeEvent) -> ImpactReport:
        report_id = f"IMP-{uuid.uuid4().hex[:8]}"

        what_changed = f"Detected {event.category.value}: {event.title} in {event.provider.value} domain."
        why_it_matters = f"Security exposure urgency: {event.urgency}. {event.description}"

        affected_components = list(event.affected_components)
        outdated_controls = []
        test_updates = []
        uncertainties = []

        desc_l = event.description.lower()

        # Component dependency resolution
        if "iam" in desc_l or "passrole" in desc_l:
            affected_components.extend(["backend.graph.iam_escalation", "rules.rules.yaml:R03"])
            outdated_controls.append("CIS-1.16: IAM Privilege Escalation Check")
            test_updates.append("tests/offline/test_redteam_graph.py::test_iam_privilege_escalation_detection_multi_hop")
        elif "s3" in desc_l or "bucket" in desc_l:
            affected_components.extend(["backend.connectors.s3", "rules.rules.yaml:SEC-S3-001"])
            outdated_controls.append("CIS-2.1.5: S3 Block Public Access")
            test_updates.append("tests/offline/test_offline_suite.py::test_s3_analyzer")
        elif "cve" in desc_l or "imdsv1" in desc_l:
            affected_components.extend(["backend.connectors.ec2", "backend.contextual_risk.engine"])
            outdated_controls.append("CIS-5.1: Ensure IMDSv2 is enforced on all EC2 instances")
            test_updates.append("tests/offline/test_integration_scenarios.py")
        elif "prompt" in desc_l or "llm" in desc_l:
            affected_components.extend(["agent.agentcore_client", "rules.rules.yaml:R01"])
            outdated_controls.append("OWASP-LLM01: Direct/Indirect Prompt Injection")
            test_updates.append("tests/offline/test_redteam_agent.py::test_agent_direct_prompt_injection_containment")
        elif "cache" in desc_l or "drift" in desc_l:
            affected_components.extend(["backend.observability.backups", "database.cache"])
            test_updates.append("tests/offline/test_redteam_operational.py")

        if event.confidence < 0.90:
            uncertainties.append("Pending multi-source corroboration before marking confirmed.")

        potential_impact = f"Severity: {event.urgency}. Potential breach or governance misalignment if unaddressed."

        return ImpactReport(
            report_id=report_id,
            event_id=event.event_id,
            what_changed=what_changed,
            why_it_matters=why_it_matters,
            affected_components=list(set(affected_components)),
            outdated_controls=outdated_controls,
            test_updates_needed=test_updates,
            potential_security_impact=potential_impact,
            urgency=event.urgency,
            supporting_evidence=event.source_observation_ids,
            uncertainties=uncertainties,
            created_at=datetime.now(timezone.utc).isoformat()
        )
