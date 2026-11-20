"""
Tests for Evidence Cryptographic Hashing Module
Verifies payload digest calculation, record hash derivation, tamper detection,
and avalanche effect on single-bit modifications.
"""

import pytest

from backend.evidence.hashing import (
    GENESIS_HASH,
    compute_payload_digest,
    compute_record_hash,
    verify_payload_digest,
    verify_record_hash,
)


def test_payload_digest_reproducibility():
    """Identical payloads with different key order yield exact same SHA-256 digest."""
    payload1 = {"bucket": "prod-data", "public": True, "tags": {"env": "prod", "tier": "gold"}}
    payload2 = {"tags": {"tier": "gold", "env": "prod"}, "public": True, "bucket": "prod-data"}

    digest1 = compute_payload_digest(payload1)
    digest2 = compute_payload_digest(payload2)

    assert len(digest1) == 64
    assert digest1 == digest2


def test_payload_avalanche_effect():
    """A 1-byte change in payload completely changes the resulting SHA-256 digest."""
    base_payload = {"resource_id": "sg-001", "port": 22, "cidr": "0.0.0.0/0"}
    altered_payload = {"resource_id": "sg-001", "port": 23, "cidr": "0.0.0.0/0"}

    base_digest = compute_payload_digest(base_payload)
    altered_digest = compute_payload_digest(altered_payload)

    assert base_digest != altered_digest
    assert verify_payload_digest(base_payload, base_digest) is True
    assert verify_payload_digest(altered_payload, base_digest) is False


def test_record_hash_includes_previous_hash():
    """Changing previous_record_hash changes the record hash."""
    record_fields = {
        "evidence_id": "EV-001",
        "resource_id": "bucket-01",
        "payload_sha256": "a" * 64
    }

    hash_with_genesis = compute_record_hash(record_fields, GENESIS_HASH)
    hash_with_other = compute_record_hash(record_fields, "f" * 64)

    assert hash_with_genesis != hash_with_other
    assert len(hash_with_genesis) == 64


def test_record_hash_excludes_itself():
    """The record_hash field is omitted during hash computation (no circular dependency)."""
    fields_without_hash = {"evidence_id": "EV-001", "resource_id": "bucket-01"}
    fields_with_dummy_hash = {
        "evidence_id": "EV-001",
        "resource_id": "bucket-01",
        "record_hash": "should_be_ignored"
    }

    hash1 = compute_record_hash(fields_without_hash, GENESIS_HASH)
    hash2 = compute_record_hash(fields_with_dummy_hash, GENESIS_HASH)

    assert hash1 == hash2


def test_verify_record_hash():
    """Validates verify_record_hash helper with matching and tampered values."""
    fields = {"evidence_id": "EV-001", "resource_id": "bucket-01"}
    computed = compute_record_hash(fields, GENESIS_HASH)

    assert verify_record_hash(fields, computed, GENESIS_HASH) is True
    # Tampered field
    fields_tampered = {"evidence_id": "EV-001", "resource_id": "bucket-02"}
    assert verify_record_hash(fields_tampered, computed, GENESIS_HASH) is False
    # Tampered prev hash
    assert verify_record_hash(fields, computed, "1" * 64) is False
