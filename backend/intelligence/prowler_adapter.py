"""
ExposureFence — Prowler v3/v4 Findings Adapter
Ingests and normalizes Prowler JSON findings into CanonicalFindings.
"""

import json
import os
from typing import Any, Dict, List, Optional

from backend.intelligence.models import CanonicalFinding, FindingSource, FindingStatus
from backend.intelligence.normalization import compute_raw_hash, normalize_arn, normalize_severity, sanitize_untrusted_text


class ProwlerAdapter:
    """Parses Prowler JSON security findings into canonical findings."""

    @staticmethod
    def parse_prowler_item(item: Dict[str, Any], default_account: str = "123456789012") -> Optional[CanonicalFinding]:
        status = item.get("Status", "").upper()
        # Only ingest failed checks
        if status != "FAIL":
            return None

        check_id = item.get("CheckID", "unknown_check")
        service = item.get("ServiceName", "aws").lower()
        region = item.get("Region", "us-east-1")
        resource_id = item.get("ResourceId", "unknown_resource")
        resource_arn = item.get("ResourceArn") or normalize_arn(resource_id, service=service, account_id=default_account, region=region)
        account_id = item.get("AccountId", default_account)

        raw_hash = compute_raw_hash(item)
        severity = normalize_severity(item.get("Severity", "medium"))
        title = sanitize_untrusted_text(item.get("CheckTitle", check_id))
        description = sanitize_untrusted_text(item.get("Description", ""))
        remediation_text = item.get("Remediation", {}).get("Recommendation", {}).get("Text")

        compliance_dict = item.get("Compliance", {})
        compliance_tags = []
        for std, controls in compliance_dict.items():
            if isinstance(controls, list):
                for c in controls:
                    compliance_tags.append(f"{std}:{c}")
            else:
                compliance_tags.append(f"{std}:{controls}")

        finding_id = f"F-PROWLER-{check_id}-{resource_id}-{raw_hash[:8]}"

        return CanonicalFinding(
            finding_id=finding_id,
            source_id=f"prowler/{check_id}/{resource_id}",
            source_type=FindingSource.PROWLER,
            raw_finding_hash=raw_hash,
            resource_arn=resource_arn,
            account_id=account_id,
            region=region,
            service=service,
            resource_type=f"AWS::{service.upper()}::{item.get('SubServiceName', 'Resource')}",
            title=title,
            description=description,
            severity=severity,
            status=FindingStatus.ACTIVE,
            raw_payload=item,
            remediation_recommendation=remediation_text,
            compliance_tags=compliance_tags
        )

    @classmethod
    def load_from_fixture(cls, fixture_path: Optional[str] = None) -> List[CanonicalFinding]:
        path = fixture_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "mock_data", "prowler_findings.json"
        )
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        findings = []
        if isinstance(data, list):
            for itm in data:
                fnd = cls.parse_prowler_item(itm)
                if fnd:
                    findings.append(fnd)
        return findings
