"""
ExposureFence Evidence Engine Cryptographic Hashing Module
Computes RFC 8785 canonical SHA-256 digests for evidence payloads and
hash-chained evidence ledger records.
"""

import hashlib
from typing import Any, Dict

from backend.evidence.canonicalization import canonicalize_json
from backend.evidence.exceptions import EvidenceIntegrityError

HASH_ALGORITHM = "SHA-256"
GENESIS_HASH = "0" * 64


def compute_payload_digest(payload: Any) -> str:
    """
    Computes deterministic SHA-256 hex digest of an evidence payload using RFC 8785 canonicalization.
    """
    canonical_bytes = canonicalize_json(payload)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_record_hash(record_fields: Dict[str, Any], previous_record_hash: str) -> str:
    """
    Computes the tamper-evident record hash for the ledger.
    Includes all canonical record fields and previous_record_hash.
    EXCLUDES the record_hash field itself to prevent circular reference.
    """
    # Create copy of record fields without self-referential or database-internal fields
    data_to_hash = {}
    excluded_fields = {"record_hash", "sequence_id", "created_at"}

    for k, v in record_fields.items():
        if k not in excluded_fields:
            data_to_hash[k] = v

    data_to_hash["previous_record_hash"] = previous_record_hash

    canonical_bytes = canonicalize_json(data_to_hash)
    return hashlib.sha256(canonical_bytes).hexdigest()


def verify_payload_digest(payload: Any, expected_digest: str) -> bool:
    """Verifies whether the canonical payload digest matches the expected SHA-256 digest."""
    if not expected_digest:
        return False
    actual_digest = compute_payload_digest(payload)
    return actual_digest.lower() == expected_digest.lower()


def verify_record_hash(record_fields: Dict[str, Any], expected_hash: str, previous_record_hash: str) -> bool:
    """Verifies that a record hash matches the expected hash computed from its canonical content."""
    if not expected_hash:
        return False
    actual_hash = compute_record_hash(record_fields, previous_record_hash)
    return actual_hash.lower() == expected_hash.lower()
