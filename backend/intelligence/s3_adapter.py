"""
ExposureFence — Native S3 Connector Adapter
Adapts native S3 findings or mock S3 data into CanonicalFinding records.
"""

import json
import os
from typing import Any, Dict, List, Optional

from backend.intelligence.models import CanonicalFinding, FindingSeverity, FindingSource, FindingStatus
from backend.intelligence.normalization import compute_raw_hash, normalize_arn, normalize_severity, sanitize_untrusted_text


class S3Adapter:
    """Adapts AWS S3 bucket exposure configurations to canonical findings."""

    @staticmethod
    def from_record(record: Dict[str, Any], account_id: str = "123456789012", region: str = "us-east-1") -> Optional[CanonicalFinding]:
        bucket_name = record.get("bucket_name") or record.get("name") or record.get("resource_id", "unknown-bucket")
        raw_hash = compute_raw_hash(record)
        resource_arn = normalize_arn(bucket_name, service="s3", account_id=account_id, region=region)

        # Check public access
        bpa = record.get("block_public_access", {})
        is_effective = bpa.get("is_effective", False)
        bucket_policy = str(record.get("bucket_policy", ""))
        is_public = record.get("public_access", False) or not is_effective or "public" in bucket_policy.lower()

        if not is_public:
            return None

        finding_id = f"F-S3-{bucket_name}-{raw_hash[:8]}"
        title = f"S3 Bucket '{bucket_name}' has public access enabled"
        description = sanitize_untrusted_text(
            f"The S3 bucket '{bucket_name}' in region '{region}' does not enforce effective Block Public Access. "
            f"Policy status: {bucket_policy}."
        )

        return CanonicalFinding(
            finding_id=finding_id,
            source_id=bucket_name,
            source_type=FindingSource.NATIVE_S3,
            raw_finding_hash=raw_hash,
            resource_arn=resource_arn,
            account_id=account_id,
            region=region,
            service="s3",
            resource_type="AWS::S3::Bucket",
            title=title,
            description=description,
            severity=FindingSeverity.CRITICAL,
            status=FindingStatus.ACTIVE,
            evidence_id=record.get("evidence_id"),
            raw_payload=record,
            remediation_recommendation="Enable S3 Block Public Access (all 4 settings) and restrict public bucket policy.",
            compliance_tags=["CIS-2.1.5", "NIST-PR.AC-3", "MITRE-T1530"]
        )

    @staticmethod
    def load_from_fixture(fixture_path: Optional[str] = None) -> List[CanonicalFinding]:
        path = fixture_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "mock_data", "s3_buckets.json"
        )
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        findings = []
        for rec in data:
            fnd = S3Adapter.from_record(rec)
            if fnd:
                findings.append(fnd)
        return findings
