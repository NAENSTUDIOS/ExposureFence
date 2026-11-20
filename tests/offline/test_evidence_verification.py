"""
Tests for Evidence Cryptographic Verification & Tamper Detection
Validates single record verification, full ledger hash chain verification,
and detection of altered payloads, broken links, or tampered hashes.
"""

from datetime import datetime, timezone
import sqlite3
import pytest

from backend.evidence.hashing import GENESIS_HASH
from backend.evidence.models import EvidenceRecord, IntegrityStatus, ProvenanceInfo, SourceMode
from backend.evidence.repository import EvidenceRepository
from backend.evidence.verifier import verify_full_ledger_chain, verify_single_record


@pytest.fixture
def temp_repo(tmp_path):
    db_file = str(tmp_path / "verification_test.db")
    return EvidenceRepository(db_path=db_file)


def make_record(ev_id: str, resource_id: str = "bucket-01") -> EvidenceRecord:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return EvidenceRecord(
        evidence_id=ev_id,
        schema_version="1.0.0",
        source_mode=SourceMode.MOCK.value,
        source_provider="SYNTHETIC_MOCK",
        source_service="s3",
        source_type="AWS::S3::Bucket",
        resource_id=resource_id,
        resource_type="AWS::S3::Bucket",
        collected_at=now_str,
        provenance=ProvenanceInfo("mock_data/s3_buckets.json", f"ACT-{ev_id}", "Collector"),
        raw_evidence={"name": resource_id, "exposure": "PUBLIC"},
        normalized_evidence={"resource_id": resource_id, "is_public": True}
    )


def test_verify_single_record_success(temp_repo):
    """Untampered record stored in repository passes single record verification."""
    rec = make_record("EV-V1")
    stored = temp_repo.store_evidence_record(rec)

    status, reason = verify_single_record(stored)
    assert status == IntegrityStatus.VERIFIED


def test_verify_single_record_payload_tamper_detected():
    """Modifying raw_evidence after digest calculation causes INTEGRITY_MISMATCH."""
    rec = make_record("EV-V2")
    # Manually compute legitimate hashes
    from backend.evidence.canonicalization import canonicalize_json_str
    from backend.evidence.hashing import compute_payload_digest, compute_record_hash
    payload = {"raw_evidence": rec.raw_evidence, "normalized_evidence": rec.normalized_evidence}
    rec.payload_sha256 = compute_payload_digest(payload)
    rec.record_hash = compute_record_hash(rec.to_dict(), GENESIS_HASH)

    # Tamper with raw_evidence
    rec.raw_evidence["name"] = "tampered-bucket"

    status, reason = verify_single_record(rec)
    assert status == IntegrityStatus.INTEGRITY_MISMATCH
    assert "Payload digest mismatch" in reason


def test_verify_full_chain_valid(temp_repo):
    """A clean chain of multiple stored records verifies 100% valid."""
    temp_repo.store_evidence_record(make_record("EV-C1"))
    temp_repo.store_evidence_record(make_record("EV-C2"))
    temp_repo.store_evidence_record(make_record("EV-C3"))

    is_valid, issues = verify_full_ledger_chain(temp_repo)
    assert is_valid is True
    assert len(issues) == 0


def test_verify_full_chain_tamper_detected(temp_repo):
    """Tampering with an intermediate record in SQLite causes verify_full_ledger_chain failure."""
    temp_repo.store_evidence_record(make_record("EV-T1"))
    temp_repo.store_evidence_record(make_record("EV-T2"))
    temp_repo.store_evidence_record(make_record("EV-T3"))

    # Bypass triggers temporarily by modifying payload_json in raw SQLite connection with PRAGMA ignore_check_constraints
    # Or test by passing an altered repository row
    conn = sqlite3.connect(temp_repo.db_path)
    # Triggers prevent UPDATE, so drop the trigger temporarily to simulate an adversary host admin altering DB
    conn.execute("DROP TRIGGER prevent_evidence_update;")
    conn.execute("UPDATE evidence_records SET payload_json = '{\"raw_evidence\":{\"hacked\":true}}' WHERE evidence_id = 'EV-T2';")
    conn.commit()
    conn.close()

    is_valid, issues = verify_full_ledger_chain(temp_repo)
    assert is_valid is False
    assert len(issues) > 0
    assert any("EV-T2" in issue for issue in issues)
