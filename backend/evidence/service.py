"""
ExposureFence Evidence Engine Service Facade
Provides the unified application interface for ingesting, querying,
verifying, and linking security evidence records.
"""

from typing import Any, Dict, List, Optional, Tuple

from backend.evidence.collector import (
    collect_from_aws_ec2,
    collect_from_aws_iam,
    collect_from_aws_s3,
    collect_from_mock_s3,
    collect_from_mock_security_groups,
)
from backend.evidence.models import (
    EntityType,
    EvidenceRecord,
    EvidenceRelationship,
    EvidenceVerificationEvent,
    IntegrityStatus,
    RelationshipType,
    SourceMode,
)
from backend.evidence.relationships import (
    bind_evidence_to_entity,
    verify_proposal_evidence_binding,
)
from backend.evidence.repository import EvidenceRepository
from backend.evidence.schema import validate_evidence_record
from backend.evidence.verifier import verify_full_ledger_chain, verify_single_record


class EvidenceService:
    """Unified service interface for the ExposureFence Evidence Engine."""

    def __init__(self, db_path: Optional[str] = None):
        self.repository = EvidenceRepository(db_path=db_path)

    def ingest_record(self, record: EvidenceRecord) -> EvidenceRecord:
        """Validates and appends a single evidence record to the ledger."""
        record_dict = record.to_dict()
        validate_evidence_record(record_dict)
        return self.repository.store_evidence_record(record)

    def ingest_mock_data(
        self,
        s3_path: str = "mock_data/s3_buckets.json",
        sg_path: str = "mock_data/security_groups.json"
    ) -> List[EvidenceRecord]:
        """
        Ingests mock S3 and Security Groups fixtures into the ledger.
        Idempotent: skips records if evidence_id already exists in the ledger.
        """
        ingested: List[EvidenceRecord] = []

        # 1. Mock S3
        s3_records = collect_from_mock_s3(s3_path)
        for r in s3_records:
            existing = self.repository.get_evidence_by_id(r.evidence_id)
            if not existing:
                stored = self.ingest_record(r)
                ingested.append(stored)
            else:
                ingested.append(existing)

        # 2. Mock Security Groups
        sg_records = collect_from_mock_security_groups(sg_path)
        for r in sg_records:
            existing = self.repository.get_evidence_by_id(r.evidence_id)
            if not existing:
                stored = self.ingest_record(r)
                ingested.append(stored)
            else:
                ingested.append(existing)

        return ingested

    def get_evidence(self, evidence_id: str) -> Optional[EvidenceRecord]:
        """Retrieves an evidence record by unique ID."""
        return self.repository.get_evidence_by_id(evidence_id)

    def list_evidence(
        self,
        limit: int = 100,
        offset: int = 0,
        source_mode: Optional[str] = None,
        resource_id: Optional[str] = None
    ) -> List[EvidenceRecord]:
        """Lists evidence records with optional filtering."""
        return self.repository.list_evidence_records(
            limit=limit,
            offset=offset,
            source_mode=source_mode,
            resource_id=resource_id
        )

    def verify_record(self, evidence_id: str) -> Tuple[IntegrityStatus, str]:
        """Verifies cryptographic integrity of a specific evidence record."""
        rec = self.repository.get_evidence_by_id(evidence_id)
        if not rec:
            return (IntegrityStatus.UNVERIFIABLE, f"Evidence '{evidence_id}' not found")
        return verify_single_record(rec)

    def verify_ledger(self) -> Tuple[bool, List[str]]:
        """Verifies the complete ledger hash chain and all individual records."""
        return verify_full_ledger_chain(self.repository)

    def link_finding(self, finding_id: str, evidence_id: str, payload_sha256: str) -> EvidenceRelationship:
        """Binds an evidence snapshot to a security finding."""
        return bind_evidence_to_entity(
            evidence_id=evidence_id,
            entity_type=EntityType.FINDING.value,
            entity_id=finding_id,
            bound_payload_sha256=payload_sha256,
            relationship_type=RelationshipType.SUPPORTS.value,
            repository=self.repository
        )

    def link_proposal(self, proposal_id: str, evidence_id: str, payload_sha256: str) -> EvidenceRelationship:
        """Binds an evidence snapshot to a remediation proposal."""
        return bind_evidence_to_entity(
            evidence_id=evidence_id,
            entity_type=EntityType.PROPOSAL.value,
            entity_id=proposal_id,
            bound_payload_sha256=payload_sha256,
            relationship_type=RelationshipType.SUPPORTS.value,
            repository=self.repository
        )

    def check_proposal_evidence(self, proposal_id: str) -> Tuple[bool, str, Optional[EvidenceRecord]]:
        """Evaluates whether a proposal's bound evidence is intact and fresh."""
        return verify_proposal_evidence_binding(proposal_id=proposal_id, repository=self.repository)

    def get_ledger_health(self) -> Dict[str, Any]:
        """Returns diagnostic health metrics for the evidence ledger."""
        count = self.repository.count_evidence_records()
        is_valid, issues = self.verify_ledger()
        latest_hash = self.repository.get_latest_record_hash()

        return {
            "total_records": count,
            "chain_valid": is_valid,
            "issues": issues,
            "latest_record_hash": latest_hash,
            "canonicalization_algorithm": "RFC-8785",
            "hash_algorithm": "SHA-256"
        }
