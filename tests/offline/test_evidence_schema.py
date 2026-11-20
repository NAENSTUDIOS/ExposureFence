"""
Tests for Phase 4 Evidence Data Contract & Schema Validation
Validates required fields, format constraints, ISO-8601 timestamps, and enum boundaries.
"""

from datetime import datetime, timezone
import pytest

from backend.evidence.exceptions import EvidenceSchemaValidationError
from backend.evidence.models import (
    AssessmentStatus,
    CollectionStatus,
    EvidenceRecord,
    FreshnessStatus,
    IntegrityStatus,
    ProvenanceInfo,
    SourceMode,
)
from backend.evidence.schema import validate_evidence_record


@pytest.fixture
def valid_record_dict():
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "evidence_id": "EV-TEST-001",
        "schema_version": "1.0.0",
        "evidence_type": "CONFIGURATION_SNAPSHOT",
        "source_mode": "MOCK",
        "source_provider": "SYNTHETIC_MOCK",
        "source_service": "s3",
        "source_type": "AWS::S3::Bucket",
        "collector_name": "ExposureFenceCollector",
        "collector_version": "1.0.0",
        "resource_id": "test-bucket-001",
        "resource_type": "AWS::S3::Bucket",
        "account_id": "123456789012",
        "region": "us-east-1",
        "resource_arn": "arn:aws:s3:::test-bucket-001",
        "collected_at": now_str,
        "observed_at": now_str,
        "provenance": {
            "source_reference": "mock_data/s3_buckets.json",
            "collection_activity_id": "ACT-TEST-001",
            "collector_identity": "ExposureFenceCollector",
            "source_payload_digest": "a" * 64,
            "parent_evidence_ids": []
        },
        "raw_evidence": {"bucket_name": "test-bucket-001", "public_access": True},
        "normalized_evidence": {"resource_id": "test-bucket-001", "effective_exposure": "PUBLIC"},
        "payload_sha256": "b" * 64,
        "canonicalization_algorithm": "RFC-8785",
        "canonicalization_version": "1.0",
        "hash_algorithm": "SHA-256",
        "previous_record_hash": "0" * 64,
        "record_hash": "c" * 64,
        "collection_status": "COLLECTED",
        "integrity_status": "VERIFIED",
        "freshness_status": "STATIC_FIXTURE",
        "assessment_status": "EXPOSURE_DETECTED"
    }


def test_valid_evidence_record(valid_record_dict):
    """Valid record passes schema validation without exception."""
    validate_evidence_record(valid_record_dict)


def test_missing_evidence_id(valid_record_dict):
    """Missing or invalid evidence_id raises EvidenceSchemaValidationError."""
    del valid_record_dict["evidence_id"]
    with pytest.raises(EvidenceSchemaValidationError, match="Missing or non-string 'evidence_id'"):
        validate_evidence_record(valid_record_dict)

    valid_record_dict["evidence_id"] = "bad id with spaces!"
    with pytest.raises(EvidenceSchemaValidationError, match="Invalid 'evidence_id' format"):
        validate_evidence_record(valid_record_dict)


def test_invalid_source_mode(valid_record_dict):
    """Invalid source mode raises EvidenceSchemaValidationError."""
    valid_record_dict["source_mode"] = "INVALID_MODE"
    with pytest.raises(EvidenceSchemaValidationError, match="Invalid 'source_mode'"):
        validate_evidence_record(valid_record_dict)


def test_missing_resource_id(valid_record_dict):
    """Missing resource_id raises EvidenceSchemaValidationError."""
    valid_record_dict["resource_id"] = ""
    with pytest.raises(EvidenceSchemaValidationError, match="Missing or non-string 'resource_id'"):
        validate_evidence_record(valid_record_dict)


def test_invalid_timestamps(valid_record_dict):
    """Invalid ISO-8601 timestamp raises EvidenceSchemaValidationError."""
    valid_record_dict["collected_at"] = "not-a-timestamp"
    with pytest.raises(EvidenceSchemaValidationError, match="Missing or invalid ISO-8601 'collected_at'"):
        validate_evidence_record(valid_record_dict)

    valid_record_dict["collected_at"] = "2026-11-21T00:00:00Z"
    valid_record_dict["observed_at"] = "invalid-date"
    with pytest.raises(EvidenceSchemaValidationError, match="Invalid ISO-8601 'observed_at'"):
        validate_evidence_record(valid_record_dict)


def test_invalid_hashes(valid_record_dict):
    """Non-64-hex hash digests are rejected."""
    valid_record_dict["payload_sha256"] = "short-hash"
    with pytest.raises(EvidenceSchemaValidationError, match="Invalid or missing 'payload_sha256'"):
        validate_evidence_record(valid_record_dict)

    valid_record_dict["payload_sha256"] = "a" * 64
    valid_record_dict["previous_record_hash"] = "invalid-prev-hash"
    with pytest.raises(EvidenceSchemaValidationError, match="Invalid or missing 'previous_record_hash'"):
        validate_evidence_record(valid_record_dict)


def test_invalid_state_enums(valid_record_dict):
    """Invalid status enum strings are rejected."""
    valid_record_dict["integrity_status"] = "ALL_GOOD"
    with pytest.raises(EvidenceSchemaValidationError, match="Invalid 'integrity_status'"):
        validate_evidence_record(valid_record_dict)

    valid_record_dict["integrity_status"] = "VERIFIED"
    valid_record_dict["freshness_status"] = "SUPER_FRESH"
    with pytest.raises(EvidenceSchemaValidationError, match="Invalid 'freshness_status'"):
        validate_evidence_record(valid_record_dict)
