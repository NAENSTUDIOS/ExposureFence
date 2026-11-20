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
            is_failed = False
            violating_findings = []

            for f in findings_list:
                if f.status.value != "ACTIVE":
                    continue

                # Finding 4 Fix: Target-specific matching rather than coarse service-level matching
                matches_control = False

                # 1. Exact control ID match in compliance_tags
                if ctrl["control_id"] in getattr(f, "compliance_tags", []):
                    matches_control = True

                # 2. Mapped related rule match in compliance_tags
                elif any(r in getattr(f, "compliance_tags", []) for r in ctrl.get("related_rules", [])):
                    matches_control = True

                # 3. Contextual finding match for target service
                elif target_srv == "all" or target_srv == f.service.lower():
                    title_l = (f.title or "").lower()
                    desc_l = (f.description or "").lower()
                    ctrl_title_l = ctrl["title"].lower()

                    if "block public access" in ctrl_title_l and ("public" in title_l or "block public" in desc_l):
                        matches_control = True
                    elif ("ssh" in ctrl_title_l or "22" in ctrl["title"]) and ("22" in title_l or "ssh" in title_l or "22" in desc_l):
                        matches_control = True
                    elif ("rdp" in ctrl_title_l or "3389" in ctrl["title"]) and ("3389" in title_l or "rdp" in title_l or "3389" in desc_l):
                        matches_control = True
                    elif ("administrative" in ctrl_title_l or "full '*:*'" in ctrl["title"]) and ("administrator" in title_l or "wildcard" in title_l or "*:*" in desc_l):
                        matches_control = True
                    elif ("least privilege" in ctrl_title_l or "access permissions" in ctrl_title_l) and ("privilege" in title_l or "admin" in title_l):
                        matches_control = True
                    elif ("network" in ctrl_title_l or "perimeter" in ctrl_title_l) and ("ingress" in title_l or "0.0.0.0/0" in desc_l):
                        matches_control = True
                    elif ("storage" in ctrl_title_l or "data-at-rest" in ctrl_title_l) and ("s3" in title_l or "bucket" in title_l):
                        matches_control = True

                if matches_control:
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
