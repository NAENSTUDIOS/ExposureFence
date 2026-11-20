"""
Tests for Evidence Repository & Append-Only Database Ledger
Validates SQLite persistence, immutability triggers (prevent UPDATE/DELETE),
hash chain sequential linking, and relationship persistence in an isolated test database.
"""

from datetime import datetime, timezone
import sqlite3
import pytest

from backend.evidence.hashing import GENESIS_HASH
from backend.evidence.models import (
    AssessmentStatus,
    CollectionStatus,
    EvidenceRecord,
    EvidenceRelationship,
    FreshnessStatus,
    IntegrityStatus,
    ProvenanceInfo,
    RelationshipType,
    SourceMode,
)
from backend.evidence.repository import EvidenceRepository, initialize_evidence_tables


@pytest.fixture
def temp_repo(tmp_path):
    """Creates an isolated temporary database for testing."""
    db_file = str(tmp_path / "isolated_evidence.db")
    repo = EvidenceRepository(db_path=db_file)
    return repo


def make_dummy_record(ev_id: str, resource_id: str = "bucket-01") -> EvidenceRecord:
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
        provenance=ProvenanceInfo("mock_data/s3_buckets.json", "ACT-001", "MockCollector"),
        raw_evidence={"bucket_name": resource_id, "public": True},
        normalized_evidence={"resource_id": resource_id, "exposure": "PUBLIC"}
    )


def test_repository_store_and_retrieve(temp_repo):
    """Stores record, verifies hash chaining, and retrieves record by ID."""
    rec1 = make_dummy_record("EV-001", "bucket-alpha")
    stored1 = temp_repo.store_evidence_record(rec1)

    assert stored1.sequence_id == 1
    assert stored1.previous_record_hash == GENESIS_HASH
    assert len(stored1.record_hash) == 64
    assert len(stored1.payload_sha256) == 64

    # Retrieve and verify equality
    retrieved = temp_repo.get_evidence_by_id("EV-001")
    assert retrieved is not None
    assert retrieved.evidence_id == "EV-001"
    assert retrieved.resource_id == "bucket-alpha"
    assert retrieved.record_hash == stored1.record_hash


def test_hash_chain_sequential_linking(temp_repo):
    """Multiple sequential records are cryptographically linked in order."""
    rec1 = make_dummy_record("EV-001", "res-1")
    rec2 = make_dummy_record("EV-002", "res-2")
    rec3 = make_dummy_record("EV-003", "res-3")

    s1 = temp_repo.store_evidence_record(rec1)
    s2 = temp_repo.store_evidence_record(rec2)
    s3 = temp_repo.store_evidence_record(rec3)

    assert s1.previous_record_hash == GENESIS_HASH
    assert s2.previous_record_hash == s1.record_hash
    assert s3.previous_record_hash == s2.record_hash


def test_duplicate_evidence_id_rejected(temp_repo):
    """Attempting to insert a duplicate evidence_id raises SQLite integrity error."""
    rec1 = make_dummy_record("EV-DUP-001", "res-1")
    temp_repo.store_evidence_record(rec1)

    rec2 = make_dummy_record("EV-DUP-001", "res-2")
    with pytest.raises(sqlite3.IntegrityError):
        temp_repo.store_evidence_record(rec2)


def test_immutability_triggers_reject_update(temp_repo):
    """SQLite triggers prevent UPDATE operations on evidence_records."""
    rec = make_dummy_record("EV-IMMUTABLE-001")
    temp_repo.store_evidence_record(rec)

    conn = sqlite3.connect(temp_repo.db_path)
    with pytest.raises(sqlite3.DatabaseError, match="Evidence records are immutable. Updates are forbidden."):
        conn.execute("UPDATE evidence_records SET resource_id = 'hacked' WHERE evidence_id = 'EV-IMMUTABLE-001'")
    conn.close()


def test_immutability_triggers_reject_delete(temp_repo):
    """SQLite triggers prevent DELETE operations on evidence_records."""
    rec = make_dummy_record("EV-NODELETE-001")
    temp_repo.store_evidence_record(rec)

    conn = sqlite3.connect(temp_repo.db_path)
    with pytest.raises(sqlite3.DatabaseError, match="Evidence records are immutable. Deletions are forbidden."):
        conn.execute("DELETE FROM evidence_records WHERE evidence_id = 'EV-NODELETE-001'")
    conn.close()


def test_relationships_storage_and_query(temp_repo):
    """Stores and queries evidence relationships."""
    rec = make_dummy_record("EV-REL-001")
    temp_repo.store_evidence_record(rec)

    rel = EvidenceRelationship(
        relationship_id="REL-001",
        evidence_id="EV-REL-001",
        entity_type="PROPOSAL",
        entity_id="PROP-999",
        relationship_type=RelationshipType.SUPPORTS.value,
        bound_payload_sha256=rec.payload_sha256
    )
    temp_repo.store_relationship(rel)

    by_ev = temp_repo.get_relationships_for_evidence("EV-REL-001")
    assert len(by_ev) == 1
    assert by_ev[0].entity_id == "PROP-999"

    by_entity = temp_repo.get_relationships_for_entity("PROPOSAL", "PROP-999")
    assert len(by_entity) == 1
    assert by_entity[0].evidence_id == "EV-REL-001"
