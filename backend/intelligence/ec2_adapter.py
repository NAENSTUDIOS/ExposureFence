"""
ExposureFence — Native EC2 Security Group Connector Adapter
Adapts native EC2 security group findings into CanonicalFinding records.
"""

import json
import os
from typing import Any, Dict, List, Optional

from backend.intelligence.models import CanonicalFinding, FindingSeverity, FindingSource, FindingStatus
from backend.intelligence.normalization import compute_raw_hash, normalize_arn, normalize_severity, sanitize_untrusted_text


class EC2Adapter:
    """Adapts AWS EC2 security group exposure configurations to canonical findings."""

    @staticmethod
    def from_record(record: Dict[str, Any], account_id: str = "123456789012", region: str = "us-east-1") -> Optional[CanonicalFinding]:
        sg_id = record.get("group_id") or record.get("sg_id") or record.get("resource_id", "unknown-sg")
        raw_hash = compute_raw_hash(record)
        resource_arn = normalize_arn(sg_id, service="ec2", account_id=account_id, region=region)

        # Evaluate open ports
        open_ssh = record.get("open_ssh_to_world", False)
        open_rdp = record.get("open_rdp_to_world", False)
        port = record.get("port")
        cidr = record.get("cidr")
        if port == 22 and cidr in ("0.0.0.0/0", "::/0"):
            open_ssh = True

        # Ingress rules check
        for rule in record.get("ingress_rules", []):
            if rule.get("cidr_ipv4") == "0.0.0.0/0" or rule.get("cidr_ipv6") == "::/0":
                if rule.get("from_port") == 22 or rule.get("to_port") == 22:
                    open_ssh = True
                if rule.get("from_port") == 3389 or rule.get("to_port") == 3389:
                    open_rdp = True

        if not open_ssh and not open_rdp:
            return None

        exposed_port = 22 if open_ssh else 3389
        proto_name = "SSH (22)" if open_ssh else "RDP (3389)"
        finding_id = f"F-SG-{sg_id}-{raw_hash[:8]}"
        title = f"Security Group '{sg_id}' allows unrestricted ingress on {proto_name}"
        description = sanitize_untrusted_text(
            f"Security group '{sg_id}' ({record.get('group_name', '')}) in VPC '{record.get('vpc_id', '')}' "
            f"permits inbound connections from 0.0.0.0/0 on administrative port {exposed_port}."
        )

        return CanonicalFinding(
            finding_id=finding_id,
            source_id=sg_id,
            source_type=FindingSource.NATIVE_EC2,
            raw_finding_hash=raw_hash,
            resource_arn=resource_arn,
            account_id=account_id,
            region=region,
            service="ec2",
            resource_type="AWS::EC2::SecurityGroup",
            title=title,
            description=description,
            severity=FindingSeverity.HIGH,
            status=FindingStatus.ACTIVE,
            evidence_id=record.get("evidence_id"),
            raw_payload=record,
            remediation_recommendation=f"Restrict port {exposed_port} ingress CIDR to trusted corporate IPs or VPN gateways.",
            compliance_tags=["CIS-5.2", "NIST-PR.AC-5", "MITRE-T1078.004"]
        )

    @staticmethod
    def load_from_fixture(fixture_path: Optional[str] = None) -> List[CanonicalFinding]:
        path = fixture_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "mock_data", "security_groups.json"
        )
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        findings = []
        for rec in data:
            fnd = EC2Adapter.from_record(rec)
            if fnd:
                findings.append(fnd)
        return findings
