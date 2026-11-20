"""
Tests for Evidence Provenance Module & W3C PROV Modeling
Validates provenance capture across mock and AWS sources and verifies W3C PROV mapping.
"""

from datetime import datetime, timezone
import pytest

from backend.evidence.models import EvidenceRecord, ProvenanceInfo, SourceMode
from backend.evidence.provenance import (
    create_aws_provenance,
    create_mock_provenance,
    export_w3c_prov_dict,
)


def test_create_mock_provenance():
    """Mock provenance captures local fixture path and fixture SHA-256 digest."""
    fixture_hash = "7adc573cb9aab105f12df1e275c627b140bba41ea0b3a2b893daf7ffd6ba220f"
    prov = create_mock_provenance("mock_data/s3_buckets.json", fixture_hash)

    assert prov.source_reference == "mock_data/s3_buckets.json"
    assert prov.source_payload_digest == fixture_hash
    assert prov.collector_identity == "ExposureFenceMockCollector/1.0"
    assert prov.collection_activity_id.startswith("ACT-MOCK-")


def test_create_aws_provenance():
    """AWS provenance captures service, API operation, account ID, and region."""
    prov = create_aws_provenance(
        service_name="s3",
        api_operation="GetBucketPublicAccessBlock",
        account_id="123456789012",
        region="us-east-1"
    )

    assert "aws://123456789012/us-east-1/s3/GetBucketPublicAccessBlock" in prov.source_reference
    assert prov.collection_activity_id.startswith("ACT-AWS-S3-")
    assert prov.collector_identity == "ExposureFenceAWSReadOnlyCollector/1.0"


def test_w3c_prov_export():
    """Exports structured W3C PROV dictionary with Entity, Activity, Agent, and PROV statements."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    prov = ProvenanceInfo(
        source_reference="mock_data/s3_buckets.json",
        collection_activity_id="ACT-001",
        collector_identity="MockAgent/1.0"
    )
    rec = EvidenceRecord(
        evidence_id="EV-PROV-001",
        resource_id="bucket-prov",
        collected_at=now_str,
        provenance=prov,
        payload_sha256="a" * 64,
        record_hash="b" * 64
    )

    prov_dict = export_w3c_prov_dict(rec)

    assert "entity" in prov_dict
    assert "activity" in prov_dict
    assert "agent" in prov_dict
    assert "wasGeneratedBy" in prov_dict
    assert "wasAttributedTo" in prov_dict
    assert "wasAssociatedWith" in prov_dict

    entity_key = "prov:entity:EV-PROV-001"
    assert entity_key in prov_dict["entity"]
    assert prov_dict["entity"][entity_key]["exposurefence:resource_id"] == "bucket-prov"
