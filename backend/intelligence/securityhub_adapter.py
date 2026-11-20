"""
ExposureFence — AWS Security Hub ASFF Adapter
Ingests and normalizes AWS Security Finding Format (ASFF) JSON records into CanonicalFindings.
"""

import json
import os
from typing import Any, Dict, List, Optional

from backend.intelligence.models import CanonicalFinding, FindingSource, FindingStatus
from backend.intelligence.normalization import compute_raw_hash, normalize_arn, normalize_severity, normalize_timestamp, sanitize_untrusted_text


class SecurityHubAdapter:
    """Parses AWS Security Hub ASFF findings into canonical findings."""

    @staticmethod
    def parse_asff_finding(finding: Dict[str, Any]) -> Optional[CanonicalFinding]:
        finding_id = finding.get("Id")
        if not finding_id:
            return None

        raw_hash = compute_raw_hash(finding)
        account_id = finding.get("AwsAccountId", "123456789012")
        title = sanitize_untrusted_text(finding.get("Title", "Untitled Security Hub Finding"))
        description = sanitize_untrusted_text(finding.get("Description", ""))

        severity_info = finding.get("Severity", {})
        raw_sev = severity_info.get("Label") or severity_info.get("Normalized", "MEDIUM")
        severity = normalize_severity(raw_sev)

        first_seen = normalize_timestamp(finding.get("FirstObservedAt") or finding.get("CreatedAt"))
        last_seen = normalize_timestamp(finding.get("LastObservedAt") or finding.get("UpdatedAt"))

        # Extract target resource
        resources = finding.get("Resources", [])
        if not resources:
            return None
        res = resources[0]
        res_id = res.get("Id", "")
        res_type = res.get("Type", "Unknown")
        region = res.get("Region") or finding.get("Region") or "us-east-1"

        # Determine service
        service = "aws"
        if "s3" in res_type.lower() or "s3" in res_id:
            service = "s3"
        elif "ec2" in res_type.lower() or "sg-" in res_id:
            service = "ec2"
        elif "iam" in res_type.lower():
            service = "iam"

        resource_arn = normalize_arn(res_id, service=service, account_id=account_id, region=region)

        # Compliance tags
        compliance = finding.get("Compliance", {})
        compliance_tags = compliance.get("RelatedRequirements", [])

        # Remediation
        remediation = finding.get("Remediation", {}).get("Recommendation", {}).get("Text")

        # Map status
        record_state = finding.get("RecordState", "ACTIVE").upper()
        status = FindingStatus.ACTIVE if record_state == "ACTIVE" else FindingStatus.RESOLVED

        canonical_id = f"F-SH-{account_id}-{raw_hash[:8]}"

        return CanonicalFinding(
            finding_id=canonical_id,
            source_id=finding_id,
            source_type=FindingSource.SECURITY_HUB,
            raw_finding_hash=raw_hash,
            resource_arn=resource_arn,
            account_id=account_id,
            region=region,
            service=service,
            resource_type=res_type,
            title=title,
            description=description,
            severity=severity,
            status=status,
            first_seen=first_seen,
            last_seen=last_seen,
            raw_payload=finding,
            remediation_recommendation=remediation,
            compliance_tags=compliance_tags
        )

    @classmethod
    def load_from_fixture(cls, fixture_path: Optional[str] = None) -> List[CanonicalFinding]:
        path = fixture_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "mock_data", "securityhub_findings.json"
        )
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        findings_list = data.get("Findings", [])
        parsed = []
        for item in findings_list:
            fnd = cls.parse_asff_finding(item)
            if fnd:
                parsed.append(fnd)
        return parsed
