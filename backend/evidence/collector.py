"""
ExposureFence Evidence Engine Collector Module
Adapts mock fixtures and read-only AWS connectors into normalized EvidenceRecords.
Enforces the same Evidence Data Contract across synthetic and live cloud data.
"""

from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List, Optional
import uuid

from backend.connectors.aws_ec2 import analyze_security_group_ingress
from backend.connectors.aws_iam import get_role_details, list_attached_role_policies
from backend.connectors.aws_s3 import (
    get_bucket_acl,
    get_bucket_policy,
    get_bucket_policy_status,
    get_bucket_public_access_block,
)
from backend.evidence.exceptions import EvidenceIntegrityError
from backend.evidence.freshness import evaluate_freshness
from backend.evidence.hashing import compute_payload_digest
from backend.evidence.models import (
    AssessmentStatus,
    CollectionStatus,
    EvidenceRecord,
    FreshnessStatus,
    IntegrityStatus,
    SourceMode,
)
from backend.evidence.provenance import create_aws_provenance, create_mock_provenance
from backend.integrity import FIXTURE_HASHES, get_fixture_hash, verify_fixture_integrity
from scoring.hashing import sha256_file


def collect_from_mock_s3(fixture_path: str = "mock_data/s3_buckets.json") -> List[EvidenceRecord]:
    """
    Ingests synthetic S3 bucket configurations from mock data fixtures.
    Validates fixture SHA-256 before ingestion.
    """
    if not os.path.exists(fixture_path):
        raise FileNotFoundError(f"Mock S3 fixture not found: {fixture_path}")

    actual_file_hash = sha256_file(fixture_path)
    expected_file_hash = get_fixture_hash(fixture_path)
    if expected_file_hash and actual_file_hash != expected_file_hash:
        raise EvidenceIntegrityError(
            f"Fixture integrity mismatch on {fixture_path}: expected {expected_file_hash}, got {actual_file_hash}"
        )

    with open(fixture_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    records: List[EvidenceRecord] = []

    for item in data:
        bucket_name = item.get("resource_id") or item.get("bucket_name", "unknown-bucket")
        is_public = item.get("public_access", False)
        evidence_id = item.get("evidence_id") or f"EV-MOCK-S3-{bucket_name}"

        assessment = (
            AssessmentStatus.EXPOSURE_DETECTED.value
            if is_public
            else AssessmentStatus.NO_ISSUE_IDENTIFIED_IN_SUPPLIED_EVIDENCE.value
        )

        raw_evidence = item
        normalized_evidence = {
            "resource_id": bucket_name,
            "resource_type": "AWS::S3::Bucket",
            "is_public": is_public,
            "policy_finding": item.get("policy_finding", "None"),
            "effective_exposure": "PUBLIC" if is_public else "RESTRICTED"
        }

        payload_data = {
            "raw_evidence": raw_evidence,
            "normalized_evidence": normalized_evidence
        }
        digest = compute_payload_digest(payload_data)

        prov = create_mock_provenance(
            fixture_path=fixture_path,
            fixture_sha256=actual_file_hash,
            activity_id=f"ACT-MOCK-S3-{digest[:8]}"
        )

        rec = EvidenceRecord(
            evidence_id=evidence_id,
            evidence_type="CONFIGURATION_SNAPSHOT",
            source_mode=SourceMode.MOCK.value,
            source_provider="SYNTHETIC_MOCK",
            source_service="s3",
            source_type="AWS::S3::Bucket",
            collector_name="ExposureFenceMockCollector",
            collector_version="1.0.0",
            resource_id=bucket_name,
            resource_type="AWS::S3::Bucket",
            account_id=item.get("account_id", "123456789012"),
            region=item.get("region", "us-east-1"),
            resource_arn=f"arn:aws:s3:::{bucket_name}",
            collected_at=timestamp,
            observed_at=item.get("timestamp", timestamp),
            provenance=prov,
            raw_evidence=raw_evidence,
            normalized_evidence=normalized_evidence,
            payload_sha256=digest,
            collection_status=CollectionStatus.COLLECTED.value,
            integrity_status=IntegrityStatus.VERIFIED.value,
            freshness_status=FreshnessStatus.STATIC_FIXTURE.value,
            assessment_status=assessment
        )
        records.append(rec)

    return records


def collect_from_mock_security_groups(fixture_path: str = "mock_data/security_groups.json") -> List[EvidenceRecord]:
    """
    Ingests synthetic EC2 security groups from mock data fixtures.
    Validates fixture SHA-256 before ingestion.
    """
    if not os.path.exists(fixture_path):
        raise FileNotFoundError(f"Mock Security Groups fixture not found: {fixture_path}")

    actual_file_hash = sha256_file(fixture_path)
    expected_file_hash = get_fixture_hash(fixture_path)
    if expected_file_hash and actual_file_hash != expected_file_hash:
        raise EvidenceIntegrityError(
            f"Fixture integrity mismatch on {fixture_path}: expected {expected_file_hash}, got {actual_file_hash}"
        )

    with open(fixture_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    records: List[EvidenceRecord] = []

    for item in data:
        sg_id = item.get("sg_id") or item.get("group_id", "sg-unknown")
        evidence_id = item.get("evidence_id") or f"EV-MOCK-SG-{sg_id}"
        cidr = item.get("cidr", "")
        port = item.get("port")
        is_exposed = (cidr in ("0.0.0.0/0", "::/0")) and (port in (22, 3389) or item.get("exposure_finding") == "SSH Open")

        assessment = (
            AssessmentStatus.EXPOSURE_DETECTED.value
            if is_exposed
            else AssessmentStatus.NO_ISSUE_IDENTIFIED_IN_SUPPLIED_EVIDENCE.value
        )

        raw_evidence = item
        normalized_evidence = {
            "resource_id": sg_id,
            "resource_type": "AWS::EC2::SecurityGroup",
            "protocol": item.get("protocol", "tcp"),
            "port": port,
            "cidr": cidr,
            "exposure_finding": item.get("exposure_finding", "None"),
            "has_unrestricted_ingress": is_exposed
        }

        payload_data = {
            "raw_evidence": raw_evidence,
            "normalized_evidence": normalized_evidence
        }
        digest = compute_payload_digest(payload_data)

        prov = create_mock_provenance(
            fixture_path=fixture_path,
            fixture_sha256=actual_file_hash,
            activity_id=f"ACT-MOCK-SG-{digest[:8]}"
        )

        rec = EvidenceRecord(
            evidence_id=evidence_id,
            evidence_type="CONFIGURATION_SNAPSHOT",
            source_mode=SourceMode.MOCK.value,
            source_provider="SYNTHETIC_MOCK",
            source_service="ec2",
            source_type="AWS::EC2::SecurityGroup",
            collector_name="ExposureFenceMockCollector",
            collector_version="1.0.0",
            resource_id=sg_id,
            resource_type="AWS::EC2::SecurityGroup",
            account_id=item.get("account_id", "123456789012"),
            region=item.get("region", "us-east-1"),
            resource_arn=f"arn:aws:ec2:us-east-1:123456789012:security-group/{sg_id}",
            collected_at=timestamp,
            observed_at=item.get("timestamp", timestamp),
            provenance=prov,
            raw_evidence=raw_evidence,
            normalized_evidence=normalized_evidence,
            payload_sha256=digest,
            collection_status=CollectionStatus.COLLECTED.value,
            integrity_status=IntegrityStatus.VERIFIED.value,
            freshness_status=FreshnessStatus.STATIC_FIXTURE.value,
            assessment_status=assessment
        )
        records.append(rec)

    return records


def collect_all_mock_evidence() -> List[EvidenceRecord]:
    """Collects mock evidence from all registered synthetic fixtures."""
    all_records: List[EvidenceRecord] = []
    all_records.extend(collect_from_mock_s3())
    all_records.extend(collect_from_mock_security_groups())
    return all_records


def collect_from_aws_s3(
    bucket_name: str,
    session=None,
    account_id: Optional[str] = None,
    region: str = "us-east-1"
) -> EvidenceRecord:
    """
    Ingests live AWS S3 bucket configuration using read-only Boto3 connector methods.
    Never accesses object contents.
    """
    pab = get_bucket_public_access_block(bucket_name, session=session)
    policy_status = get_bucket_policy_status(bucket_name, session=session)
    acl_status = get_bucket_acl(bucket_name, session=session)

    is_public = (not pab.get("is_effective", False)) and (
        policy_status.get("is_public", False) or acl_status.get("is_public_acl", False)
    )

    assessment = (
        AssessmentStatus.EXPOSURE_DETECTED.value
        if is_public
        else AssessmentStatus.NO_ISSUE_IDENTIFIED_IN_SUPPLIED_EVIDENCE.value
    )

    raw_evidence = {
        "bucket_name": bucket_name,
        "public_access_block": pab,
        "policy_status": policy_status,
        "acl_status": acl_status
    }
    normalized_evidence = {
        "resource_id": bucket_name,
        "resource_type": "AWS::S3::Bucket",
        "is_public_access_blocked": pab.get("is_effective", False),
        "is_policy_public": policy_status.get("is_public", False),
        "is_acl_public": acl_status.get("is_public_acl", False),
        "effective_exposure": "PUBLIC" if is_public else "RESTRICTED"
    }

    payload_data = {
        "raw_evidence": raw_evidence,
        "normalized_evidence": normalized_evidence
    }
    digest = compute_payload_digest(payload_data)
    evidence_id = f"EV-AWS-S3-{bucket_name}-{digest[:8]}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    prov = create_aws_provenance(
        service_name="s3",
        api_operation="GetBucketPublicAccessBlock+GetBucketPolicyStatus+GetBucketAcl",
        account_id=account_id,
        region=region
    )

    rec = EvidenceRecord(
        evidence_id=evidence_id,
        evidence_type="CONFIGURATION_SNAPSHOT",
        source_mode=SourceMode.AWS_READ_ONLY.value,
        source_provider="AWS",
        source_service="s3",
        source_type="AWS::S3::Bucket",
        collector_name="ExposureFenceAWSReadOnlyCollector",
        collector_version="1.0.0",
        resource_id=bucket_name,
        resource_type="AWS::S3::Bucket",
        account_id=account_id,
        region=region,
        resource_arn=f"arn:aws:s3:::{bucket_name}",
        collected_at=timestamp,
        observed_at=timestamp,
        provenance=prov,
        raw_evidence=raw_evidence,
        normalized_evidence=normalized_evidence,
        payload_sha256=digest,
        collection_status=CollectionStatus.COLLECTED.value,
        integrity_status=IntegrityStatus.VERIFIED.value,
        freshness_status=FreshnessStatus.FRESH.value,
        assessment_status=assessment
    )

    rec.freshness_status = evaluate_freshness(rec).value
    return rec


def collect_from_aws_ec2(
    sg_dict: Dict[str, Any],
    session=None,
    account_id: Optional[str] = None,
    region: str = "us-east-1"
) -> EvidenceRecord:
    """
    Ingests live AWS EC2 security group ingress configuration.
    """
    sg_id = sg_dict.get("GroupId", "unknown-sg")
    exposures = analyze_security_group_ingress(sg_dict)
    is_exposed = len(exposures) > 0

    assessment = (
        AssessmentStatus.EXPOSURE_DETECTED.value
        if is_exposed
        else AssessmentStatus.NO_ISSUE_IDENTIFIED_IN_SUPPLIED_EVIDENCE.value
    )

    raw_evidence = sg_dict
    normalized_evidence = {
        "resource_id": sg_id,
        "resource_type": "AWS::EC2::SecurityGroup",
        "group_name": sg_dict.get("GroupName", ""),
        "vpc_id": sg_dict.get("VpcId", ""),
        "public_ingress_rules": exposures,
        "has_unrestricted_ingress": is_exposed
    }

    payload_data = {
        "raw_evidence": raw_evidence,
        "normalized_evidence": normalized_evidence
    }
    digest = compute_payload_digest(payload_data)
    evidence_id = f"EV-AWS-SG-{sg_id}-{digest[:8]}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    prov = create_aws_provenance(
        service_name="ec2",
        api_operation="DescribeSecurityGroups",
        account_id=account_id,
        region=region
    )

    rec = EvidenceRecord(
        evidence_id=evidence_id,
        evidence_type="CONFIGURATION_SNAPSHOT",
        source_mode=SourceMode.AWS_READ_ONLY.value,
        source_provider="AWS",
        source_service="ec2",
        source_type="AWS::EC2::SecurityGroup",
        collector_name="ExposureFenceAWSReadOnlyCollector",
        collector_version="1.0.0",
        resource_id=sg_id,
        resource_type="AWS::EC2::SecurityGroup",
        account_id=account_id,
        region=region,
        resource_arn=f"arn:aws:ec2:{region}:{account_id or 'unknown'}:security-group/{sg_id}",
        collected_at=timestamp,
        observed_at=timestamp,
        provenance=prov,
        raw_evidence=raw_evidence,
        normalized_evidence=normalized_evidence,
        payload_sha256=digest,
        collection_status=CollectionStatus.COLLECTED.value,
        integrity_status=IntegrityStatus.VERIFIED.value,
        freshness_status=FreshnessStatus.FRESH.value,
        assessment_status=assessment
    )

    rec.freshness_status = evaluate_freshness(rec).value
    return rec


def collect_from_aws_iam(
    role_name: str,
    session=None,
    account_id: Optional[str] = None
) -> EvidenceRecord:
    """
    Ingests live AWS IAM role configuration and attached policies.
    """
    details = get_role_details(role_name, session=session)
    attached = list_attached_role_policies(role_name, session=session)
    has_admin = any(p.get("is_admin_policy", False) for p in attached)

    assessment = (
        AssessmentStatus.EXPOSURE_DETECTED.value
        if has_admin
        else AssessmentStatus.NO_ISSUE_IDENTIFIED_IN_SUPPLIED_EVIDENCE.value
    )

    raw_evidence = {
        "role_details": details,
        "attached_policies": attached
    }
    normalized_evidence = {
        "resource_id": role_name,
        "resource_type": "AWS::IAM::Role",
        "arn": details.get("arn", ""),
        "has_administrator_access": has_admin,
        "attached_policy_count": len(attached)
    }

    payload_data = {
        "raw_evidence": raw_evidence,
        "normalized_evidence": normalized_evidence
    }
    digest = compute_payload_digest(payload_data)
    evidence_id = f"EV-AWS-IAM-{role_name}-{digest[:8]}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    prov = create_aws_provenance(
        service_name="iam",
        api_operation="GetRole+ListAttachedRolePolicies",
        account_id=account_id,
        region="global"
    )

    rec = EvidenceRecord(
        evidence_id=evidence_id,
        evidence_type="CONFIGURATION_SNAPSHOT",
        source_mode=SourceMode.AWS_READ_ONLY.value,
        source_provider="AWS",
        source_service="iam",
        source_type="AWS::IAM::Role",
        collector_name="ExposureFenceAWSReadOnlyCollector",
        collector_version="1.0.0",
        resource_id=role_name,
        resource_type="AWS::IAM::Role",
        account_id=account_id,
        region="global",
        resource_arn=details.get("arn", f"arn:aws:iam::{account_id or 'unknown'}:role/{role_name}"),
        collected_at=timestamp,
        observed_at=timestamp,
        provenance=prov,
        raw_evidence=raw_evidence,
        normalized_evidence=normalized_evidence,
        payload_sha256=digest,
        collection_status=CollectionStatus.COLLECTED.value,
        integrity_status=IntegrityStatus.VERIFIED.value,
        freshness_status=FreshnessStatus.FRESH.value,
        assessment_status=assessment
    )

    rec.freshness_status = evaluate_freshness(rec).value
    return rec
