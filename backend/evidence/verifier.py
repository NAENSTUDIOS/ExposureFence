"""
ExposureFence Evidence Engine Verification Module
Performs cryptographic verification of evidence payloads and ledger hash chains.
Detects tampering, missing records, payload alterations, and broken hash links.
"""

from typing import List, Optional, Tuple

from backend.evidence.hashing import (
    GENESIS_HASH,
    compute_payload_digest,
    compute_record_hash,
)
from backend.evidence.models import EvidenceRecord, IntegrityStatus
from backend.evidence.repository import EvidenceRepository


def verify_single_record(record: EvidenceRecord) -> Tuple[IntegrityStatus, str]:
    """
    Verifies the cryptographic integrity of an individual evidence record.
    Checks:
      1. Canonical payload SHA-256 digest recomputation
      2. Record hash recomputation
    """
    # 1. Verify payload digest
    payload_data = {
        "raw_evidence": record.raw_evidence,
        "normalized_evidence": record.normalized_evidence
    }
    recomputed_payload_digest = compute_payload_digest(payload_data)
    if recomputed_payload_digest.lower() != record.payload_sha256.lower():
        return (
            IntegrityStatus.INTEGRITY_MISMATCH,
            f"Payload digest mismatch on evidence '{record.evidence_id}': "
            f"expected {record.payload_sha256}, got {recomputed_payload_digest}"
        )

    # 2. Verify record hash
    recomputed_record_hash = compute_record_hash(record.to_dict(), record.previous_record_hash)
    if recomputed_record_hash.lower() != record.record_hash.lower():
        return (
            IntegrityStatus.INTEGRITY_MISMATCH,
            f"Record hash mismatch on evidence '{record.evidence_id}': "
            f"expected {record.record_hash}, got {recomputed_record_hash}"
        )

    return (IntegrityStatus.VERIFIED, "Cryptographic integrity verified")


def verify_full_ledger_chain(repo: Optional[EvidenceRepository] = None) -> Tuple[bool, List[str]]:
    """
    Validates the entire evidence ledger hash chain from Genesis.
    Checks:
      - Genesis record points to GENESIS_HASH (0000...0000)
      - Every sequential record's previous_record_hash matches previous record_hash
      - Recomputes payload and record hashes for every record
      - Detects broken links, out-of-order sequences, and payload alterations
    Returns (is_valid: bool, issues: List[str]).
    """
    repository = repo or EvidenceRepository()
    records = repository.list_evidence_records(limit=10000, offset=0)

    if not records:
        return (True, [])

    issues: List[str] = []
    expected_prev_hash = GENESIS_HASH
    seen_ids = set()

    for i, rec in enumerate(records):
        # 1. Duplicate ID check
        if rec.evidence_id in seen_ids:
            issues.append(f"Duplicate evidence ID detected at sequence {rec.sequence_id}: {rec.evidence_id}")
        seen_ids.add(rec.evidence_id)

        # 2. Previous hash link check
        if rec.previous_record_hash.lower() != expected_prev_hash.lower():
            issues.append(
                f"Broken hash chain at sequence {rec.sequence_id} (evidence '{rec.evidence_id}'): "
                f"previous_record_hash={rec.previous_record_hash}, expected={expected_prev_hash}"
            )

        # 3. Individual record integrity check
        status, reason = verify_single_record(rec)
        if status != IntegrityStatus.VERIFIED:
            issues.append(f"Integrity violation on evidence '{rec.evidence_id}': {reason}")

        expected_prev_hash = rec.record_hash

    is_valid = len(issues) == 0
    return (is_valid, issues)
