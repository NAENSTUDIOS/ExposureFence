"""
ExposureFence — Native IAM Connector Adapter
Adapts native IAM role and policy exposure data into CanonicalFinding records.
"""

from typing import Any, Dict, List, Optional

from backend.intelligence.models import CanonicalFinding, FindingSeverity, FindingSource, FindingStatus
from backend.intelligence.normalization import compute_raw_hash, normalize_arn, sanitize_untrusted_text


class IAMAdapter:
    """Adapts AWS IAM role and privilege exposure to canonical findings."""

    @staticmethod
    def from_record(record: Dict[str, Any], account_id: str = "123456789012") -> Optional[CanonicalFinding]:
        role_name = record.get("resource_id") or record.get("role_name", "unknown-role")
        raw_hash = compute_raw_hash(record)
        resource_arn = normalize_arn(role_name, service="iam", account_id=account_id)

        has_admin = record.get("has_administrator_access", False)
        # Check attached policies
        for p in record.get("attached_policies", []):
            if p.get("policy_name") == "AdministratorAccess" or p.get("is_admin_policy"):
                has_admin = True

        if not has_admin:
            return None

        finding_id = f"F-IAM-{role_name}-{raw_hash[:8]}"
        title = f"IAM Role '{role_name}' possesses unrestricted AdministratorAccess"
        description = sanitize_untrusted_text(
            f"The IAM role '{role_name}' has AdministratorAccess policy attached, violating the principle of least privilege."
        )

        return CanonicalFinding(
            finding_id=finding_id,
            source_id=role_name,
            source_type=FindingSource.NATIVE_IAM,
            raw_finding_hash=raw_hash,
            resource_arn=resource_arn,
            account_id=account_id,
            region="global",
            service="iam",
            resource_type="AWS::IAM::Role",
            title=title,
            description=description,
            severity=FindingSeverity.HIGH,
            status=FindingStatus.ACTIVE,
            evidence_id=record.get("evidence_id"),
            raw_payload=record,
            remediation_recommendation="Detach AdministratorAccess and replace with least-privilege scoped permissions.",
            compliance_tags=["CIS-1.16", "NIST-PR.AC-6", "MITRE-T1098"]
        )
