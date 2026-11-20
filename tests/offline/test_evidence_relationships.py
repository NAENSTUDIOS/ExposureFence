"""
Tests for Evidence-to-Action Relationships & Proposal Governance
Validates evidence-to-proposal binding, stale evidence approval gating,
tamper detection, and backward-compatible legacy proposal handling.
"""

from datetime import datetime, timedelta, timezone
import pytest

from backend.approvals import approve_by_id
from backend.evidence.models import EvidenceRecord, ProvenanceInfo, SourceMode
from backend.evidence.relationships import (
    bind_evidence_to_entity,
    verify_proposal_evidence_binding,
)
from backend.evidence.repository import EvidenceRepository
from backend.proposals import create_proposal
from backend.session_store import create_session


@pytest.fixture
def temp_repo(tmp_path):
    db_file = str(tmp_path / "relationship_test.db")
    return EvidenceRepository(db_path=db_file)


def make_test_evidence(ev_id: str, collected_time: str, source_mode: str = "MOCK") -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=ev_id,
        schema_version="1.0.0",
        source_mode=source_mode,
        source_provider="SYNTHETIC_MOCK" if source_mode == "MOCK" else "AWS",
        source_service="s3",
        source_type="AWS::S3::Bucket",
        resource_id="bucket-target-001",
        resource_type="AWS::S3::Bucket",
        collected_at=collected_time,
        provenance=ProvenanceInfo("mock_data/s3_buckets.json", f"ACT-{ev_id}", "Collector"),
        raw_evidence={"bucket": "bucket-target-001", "public": True},
        normalized_evidence={"resource_id": "bucket-target-001", "exposure": "PUBLIC"}
    )


def test_legacy_unbound_proposal_verification(temp_repo):
    """Proposals with no evidence relationships return LEGACY_UNBOUND and allow approval."""
    can_proceed, reason, ev = verify_proposal_evidence_binding("LEGACY-PROP-001", repository=temp_repo)
    assert can_proceed is True
    assert "LEGACY_UNBOUND" in reason
    assert ev is None


def test_bound_fresh_evidence_verification(temp_repo):
    """Proposals bound to fresh evidence pass verification."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rec = make_test_evidence("EV-FRESH-001", now_str, source_mode="AWS_READ_ONLY")
    stored = temp_repo.store_evidence_record(rec)

    bind_evidence_to_entity(
        evidence_id="EV-FRESH-001",
        entity_type="PROPOSAL",
        entity_id="PROP-FRESH-001",
        bound_payload_sha256=stored.payload_sha256,
        repository=temp_repo
    )

    can_proceed, reason, ev = verify_proposal_evidence_binding("PROP-FRESH-001", repository=temp_repo)
    assert can_proceed is True
    assert "VERIFIED_AND_FRESH" in reason
    assert ev is not None


def test_tampered_binding_digest_rejection(temp_repo):
    """If bound payload SHA-256 does not match current record digest, verification fails."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rec = make_test_evidence("EV-TAMPER-001", now_str)
    stored = temp_repo.store_evidence_record(rec)

    # Bind with a fabricated hash
    bind_evidence_to_entity(
        evidence_id="EV-TAMPER-001",
        entity_type="PROPOSAL",
        entity_id="PROP-TAMPER-001",
        bound_payload_sha256="f" * 64,
        repository=temp_repo
    )

    can_proceed, reason, ev = verify_proposal_evidence_binding("PROP-TAMPER-001", repository=temp_repo)
    assert can_proceed is False
    assert "TAMPERED_BINDING" in reason


def test_stale_evidence_blocks_verification(temp_repo):
    """Live AWS evidence older than max age policy fails verification."""
    now = datetime.now(timezone.utc)
    old_time = (now - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")

    rec = make_test_evidence("EV-STALE-001", old_time, source_mode="AWS_READ_ONLY")
    stored = temp_repo.store_evidence_record(rec)

    bind_evidence_to_entity(
        evidence_id="EV-STALE-001",
        entity_type="PROPOSAL",
        entity_id="PROP-STALE-001",
        bound_payload_sha256=stored.payload_sha256,
        repository=temp_repo
    )

    can_proceed, reason, ev = verify_proposal_evidence_binding("PROP-STALE-001", repository=temp_repo)
    assert can_proceed is False
    assert "STALE_EVIDENCE" in reason
