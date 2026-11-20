"""
ExposureFence — Compliance Evaluation Service
Computes real-time framework compliance posture and control coverage percentages
based on active findings and rule evaluation results.
"""

from collections import defaultdict
from typing import Any, Dict, List, Optional

from backend.compliance.mappings import FRAMEWORK_CONTROLS
from backend.intelligence.models import CanonicalFinding


class ComplianceService:
    """Evaluates compliance posture across all supported security frameworks."""

    @staticmethod
    def evaluate_compliance(findings: Optional[List[CanonicalFinding]] = None) -> Dict[str, Any]:
        findings_list = findings or []

        # Map violated services
        violated_services = {f.service.lower() for f in findings_list if f.status.value == "ACTIVE"}

        framework_summary: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "total_controls": 0,
            "passed_controls": 0,
            "failed_controls": 0,
            "coverage_percentage": 0.0,
            "controls": []
        })

        for ctrl in FRAMEWORK_CONTROLS:
            fw = ctrl["framework"]
            framework_summary[fw]["total_controls"] += 1

            target_srv = ctrl.get("target_service", "all")
            # If target service has active findings, control fails
            is_failed = False
            violating_findings = []

            for f in findings_list:
                if f.status.value != "ACTIVE":
                    continue
                if target_srv == "all" or target_srv == f.service.lower():
                    # Check if finding title or tags match control
                    if ctrl["control_id"] in str(f.compliance_tags) or target_srv == f.service.lower():
                        is_failed = True
                        violating_findings.append(f.finding_id)

            if is_failed:
                framework_summary[fw]["failed_controls"] += 1
                status = "FAILED"
            else:
                framework_summary[fw]["passed_controls"] += 1
                status = "PASSED"

            framework_summary[fw]["controls"].append({
                "control_id": ctrl["control_id"],
                "title": ctrl["title"],
                "description": ctrl["description"],
                "status": status,
                "related_rules": ctrl["related_rules"],
                "violating_findings": violating_findings
            })

        # Calculate coverage percentages
        for fw, data in framework_summary.items():
            tot = data["total_controls"]
            passed = data["passed_controls"]
            data["coverage_percentage"] = round((passed / tot) * 100.0, 1) if tot > 0 else 0.0

        return dict(framework_summary)
