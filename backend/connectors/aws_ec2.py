"""
ExposureFence AWS EC2 Security Group Read-Only Connector
Inspects EC2 security group ingress rules for unrestricted public CIDRs (0.0.0.0/0) and exposed ports.
STRICTLY READ-ONLY: Never authorizes, revokes, creates, or deletes security group rules.
"""

from datetime import datetime, UTC
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError
from backend.connectors.aws_session import get_boto3_session
from backend.connectors.evidence_status import AssessmentStatus, build_failure_evidence, map_error_to_assessment_status

logger = logging.getLogger("exposurefence.connectors.ec2")


def describe_security_groups(group_ids: Optional[List[str]] = None, session=None) -> List[Dict[str, Any]]:
    """Describes security groups in the configured region. Read-only."""
    sess = session or get_boto3_session()
    client = sess.client("ec2")
    kwargs = {}
    if group_ids:
        kwargs["GroupIds"] = group_ids

    response = client.describe_security_groups(**kwargs)
    return response.get("SecurityGroups", [])


def analyze_security_group_ingress(sg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluates ingress rules within a security group for open public exposure (0.0.0.0/0 or ::/0).
    """
    findings = []
    sg_id = sg.get("GroupId", "unknown")
    sg_name = sg.get("GroupName", "")

    for perm in sg.get("IpPermissions", []):
        ip_protocol = perm.get("IpProtocol", "")
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")

        # Check IPv4 public CIDRs
        for ip_range in perm.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "")
            if cidr == "0.0.0.0/0":
                findings.append({
                    "sg_id": sg_id,
                    "sg_name": sg_name,
                    "protocol": ip_protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": cidr,
                    "is_ssh_exposed": (from_port == 22 or (from_port is not None and to_port is not None and from_port <= 22 <= to_port)),
                    "is_rdp_exposed": (from_port == 3389 or (from_port is not None and to_port is not None and from_port <= 3389 <= to_port))
                })

        # Check IPv6 public CIDRs
        for ipv6_range in perm.get("Ipv6Ranges", []):
            cidr_v6 = ipv6_range.get("CidrIpv6", "")
            if cidr_v6 == "::/0":
                findings.append({
                    "sg_id": sg_id,
                    "sg_name": sg_name,
                    "protocol": ip_protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": cidr_v6,
                    "is_ssh_exposed": (from_port == 22 or (from_port is not None and to_port is not None and from_port <= 22 <= to_port)),
                    "is_rdp_exposed": (from_port == 3389 or (from_port is not None and to_port is not None and from_port <= 3389 <= to_port))
                })

    return findings


def collect_ec2_exposure_evidence(sg: Dict[str, Any], session=None, account_id: Optional[str] = None, region: str = "us-east-1") -> Dict[str, Any]:
    """
    Analyzes a security group and produces a normalized Evidence record.
    Maps API errors to explicit failure states (never clean/secure).
    """
    sg_id = sg.get("GroupId", "unknown")
    try:
        exposures = analyze_security_group_ingress(sg)
    except Exception as exc:
        logger.warning("Error analyzing EC2 security group %s: %s", sg_id, exc)
        status = map_error_to_assessment_status(exc)
        return build_failure_evidence(
            resource_id=sg_id,
            source_type="AWS::EC2::SecurityGroup",
            status=status,
            error_message=str(exc),
            account_id=account_id,
            region=region
        )

    raw_evidence = {
        "resource_id": sg_id,
        "group_name": sg.get("GroupName"),
        "vpc_id": sg.get("VpcId"),
        "public_ingress_rules": exposures,
        "is_exposed": len(exposures) > 0
    }

    canonical_raw = json.dumps(raw_evidence, sort_keys=True)
    digest = hashlib.sha256(canonical_raw.encode("utf-8")).hexdigest()
    timestamp = datetime.now(UTC).isoformat()
    evidence_id = f"EV-AWS-SG-{sg_id}-{digest[:8]}"

    return {
        "evidence_id": evidence_id,
        "resource_id": sg_id,
        "source_type": "AWS::EC2::SecurityGroup",
        "account_id": account_id,
        "region": region,
        "collection_timestamp": timestamp,
        "raw_evidence": raw_evidence,
        "sha256": digest,
        "verification_result": "EXPOSURE_DETECTED" if len(exposures) > 0 else "VERIFIED_SECURE"
    }
