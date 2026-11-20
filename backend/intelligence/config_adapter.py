"""
ExposureFence — AWS Config Compliance Adapter
Ingests and normalizes AWS Config compliance evaluation results into CanonicalFindings.
"""

import json
import os
from typing import Any, Dict, List, Optional

from backend.intelligence.models import CanonicalFinding, FindingSeverity, FindingSource, FindingStatus
from backend.intelligence.normalization import compute_raw_hash, normalize_arn, normalize_timestamp, sanitize_untrusted_text


class AWSConfigAdapter:
    """Parses AWS Config compliance evaluation records into canonical findings."""

    @staticmethod
    def parse_evaluation_result(result: Dict[str, Any], account_id: str = "123456789012", region: str = "us-east-1") -> Optional[CanonicalFinding]:
        compliance_type = result.get("ComplianceType", "NOT_APPLICABLE")
        # Only ingest non-compliant results as findings
        if compliance_type != "NON_COMPLIANT":
            return None

        identifier = result.get("EvaluationResultIdentifier", {})
        qualifier = identifier.get("EvaluationResultQualifier", {})
        rule_name = qualifier.get("ConfigRuleName", "unknown-rule")
        resource_type = qualifier.get("ResourceType", "AWS::Resource")
        resource_id = qualifier.get("ResourceId", "unknown-resource")

        raw_hash = compute_raw_hash(result)
        service = "aws"
        if "s3" in resource_type.lower():
            service = "s3"
        elif "ec2" in resource_type.lower():
            service = "ec2"
        elif "iam" in resource_type.lower():
            service = "iam"

        resource_arn = normalize_arn(resource_id, service=service, account_id=account_id, region=region)
        annotation = sanitize_untrusted_text(result.get("Annotation", f"AWS Config rule '{rule_name}' evaluated to NON_COMPLIANT"))
        recorded_time = normalize_timestamp(result.get("ResultRecordedTime"))

        # Map severity based on rule type
        severity = FindingSeverity.HIGH
        if "public" in rule_name or "admin" in rule_name:
            severity = FindingSeverity.CRITICAL

        finding_id = f"F-CFG-{rule_name}-{resource_id}-{raw_hash[:8]}"

        return CanonicalFinding(
            finding_id=finding_id,
            source_id=f"{rule_name}/{resource_id}",
            source_type=FindingSource.AWS_CONFIG,
            raw_finding_hash=raw_hash,
            resource_arn=resource_arn,
            account_id=account_id,
            region=region,
            service=service,
            resource_type=resource_type,
            title=f"AWS Config Non-Compliant: {rule_name} on {resource_id}",
            description=annotation,
            severity=severity,
            status=FindingStatus.ACTIVE,
            first_seen=recorded_time,
            last_seen=recorded_time,
            raw_payload=result,
            remediation_recommendation=f"Remediate resource to comply with AWS Config managed rule {rule_name}.",
            compliance_tags=[f"AWSConfig:{rule_name}"]
        )

    @classmethod
    def load_from_fixture(cls, fixture_path: Optional[str] = None) -> List[CanonicalFinding]:
        path = fixture_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "mock_data", "config_compliance.json"
        )
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        results = data.get("EvaluationResults", [])
        findings = []
        for res in results:
            fnd = cls.parse_evaluation_result(res)
            if fnd:
                findings.append(fnd)
        return findings
