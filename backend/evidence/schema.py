"""
ExposureFence Evidence Engine Schema Validation Module
Enforces the versioned Evidence Data Contract across all ingestion sources.
"""

from datetime import datetime
import re
from typing import Any, Dict

from backend.evidence.exceptions import EvidenceSchemaValidationError
from backend.evidence.models import (
    AssessmentStatus,
    CollectionStatus,
    FreshnessStatus,
    IntegrityStatus,
    SourceMode,
)

SCHEMA_VERSION = "1.0.0"
HEX_64_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
EVIDENCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-\.:]{3,128}$")


def _is_valid_iso8601(dt_str: str) -> bool:
    if not dt_str or not isinstance(dt_str, str):
        return False
    try:
        # Replace trailing Z for fromisoformat compatibility
        clean = dt_str.replace("Z", "+00:00")
        datetime.fromisoformat(clean)
        return True
    except Exception:
        return False


def validate_evidence_record(record: Dict[str, Any]) -> None:
    """
    Validates that a dictionary conforms strictly to the Evidence Data Contract (v1.0.0).
    Raises EvidenceSchemaValidationError if required fields are missing or invalid.
    """
    if not isinstance(record, dict):
        raise EvidenceSchemaValidationError("Evidence record must be a dictionary")

    # 1. Identity
    evidence_id = record.get("evidence_id")
    if not evidence_id or not isinstance(evidence_id, str):
        raise EvidenceSchemaValidationError("Missing or non-string 'evidence_id'")
    if not EVIDENCE_ID_PATTERN.match(evidence_id):
        raise EvidenceSchemaValidationError(f"Invalid 'evidence_id' format: {evidence_id}")

    schema_version = record.get("schema_version", SCHEMA_VERSION)
    if not schema_version or not isinstance(schema_version, str):
        raise EvidenceSchemaValidationError("Missing or non-string 'schema_version'")

    # 2. Source
    source_mode = record.get("source_mode")
    valid_modes = {m.value for m in SourceMode}
    if source_mode not in valid_modes:
        raise EvidenceSchemaValidationError(f"Invalid 'source_mode': {source_mode}. Must be one of {valid_modes}")

    # 3. Resource
    resource_id = record.get("resource_id")
    if not resource_id or not isinstance(resource_id, str):
        raise EvidenceSchemaValidationError("Missing or non-string 'resource_id'")

    # 4. Timestamps
    collected_at = record.get("collected_at")
    if not collected_at or not _is_valid_iso8601(collected_at):
        raise EvidenceSchemaValidationError(f"Missing or invalid ISO-8601 'collected_at': {collected_at}")

    observed_at = record.get("observed_at")
    if observed_at and not _is_valid_iso8601(observed_at):
        raise EvidenceSchemaValidationError(f"Invalid ISO-8601 'observed_at': {observed_at}")

    # 5. Provenance
    prov = record.get("provenance")
    if not isinstance(prov, dict):
        raise EvidenceSchemaValidationError("Missing or invalid 'provenance' sub-dictionary")
    if not prov.get("source_reference"):
        raise EvidenceSchemaValidationError("Missing 'source_reference' in provenance")
    if not prov.get("collection_activity_id"):
        raise EvidenceSchemaValidationError("Missing 'collection_activity_id' in provenance")

    # 6. Payload
    if "raw_evidence" not in record or not isinstance(record["raw_evidence"], dict):
        raise EvidenceSchemaValidationError("Missing or non-dictionary 'raw_evidence'")

    payload_sha256 = record.get("payload_sha256")
    if not payload_sha256 or not HEX_64_PATTERN.match(payload_sha256):
        raise EvidenceSchemaValidationError(f"Invalid or missing 'payload_sha256': {payload_sha256}")

    # 7. Cryptographic metadata
    prev_hash = record.get("previous_record_hash")
    if not prev_hash or not HEX_64_PATTERN.match(prev_hash):
        raise EvidenceSchemaValidationError(f"Invalid or missing 'previous_record_hash': {prev_hash}")

    rec_hash = record.get("record_hash")
    if rec_hash and not HEX_64_PATTERN.match(rec_hash):
        raise EvidenceSchemaValidationError(f"Invalid 'record_hash' format: {rec_hash}")

    # 8. Verification state enums
    coll_status = record.get("collection_status")
    valid_coll = {s.value for s in CollectionStatus}
    if coll_status and coll_status not in valid_coll:
        raise EvidenceSchemaValidationError(f"Invalid 'collection_status': {coll_status}")

    integ_status = record.get("integrity_status")
    valid_integ = {s.value for s in IntegrityStatus}
    if integ_status and integ_status not in valid_integ:
        raise EvidenceSchemaValidationError(f"Invalid 'integrity_status': {integ_status}")

    fresh_status = record.get("freshness_status")
    valid_fresh = {s.value for s in FreshnessStatus}
    if fresh_status and fresh_status not in valid_fresh:
        raise EvidenceSchemaValidationError(f"Invalid 'freshness_status': {fresh_status}")

    assess_status = record.get("assessment_status")
    valid_assess = {s.value for s in AssessmentStatus}
    if assess_status and assess_status not in valid_assess:
        raise EvidenceSchemaValidationError(f"Invalid 'assessment_status': {assess_status}")
