"""
ExposureFence Evidence Engine Repository Module
Implements persistent SQLite ledger storage, append-only triggers,
index optimization, and thread-safe serializable hash-chain transactions.
"""

import json
import sqlite3
from typing import Any, Dict, List, Optional

from backend.database import DB_PATH, get_connection
from backend.evidence.canonicalization import canonicalize_json_str
from backend.evidence.exceptions import EvidenceNotFoundError, EvidenceTamperingError
from backend.evidence.hashing import GENESIS_HASH, compute_payload_digest, compute_record_hash
from backend.evidence.models import (
    EvidenceRecord,
    EvidenceRelationship,
    EvidenceVerificationEvent,
    ProvenanceInfo,
)


def initialize_evidence_tables(db_path: Optional[str] = None) -> None:
    """
    Initializes evidence ledger tables and immutability triggers.
    Purely additive; does not alter existing tables or delete data.
    """
    target_path = db_path or DB_PATH
    conn = sqlite3.connect(target_path, timeout=20.0)
    cursor = conn.cursor()

    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA foreign_keys=ON;")

    # 1. Evidence Records Ledger Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence_records (
            sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT UNIQUE NOT NULL,
            schema_version TEXT NOT NULL,
            source_mode TEXT NOT NULL,
            source_provider TEXT NOT NULL,
            source_service TEXT NOT NULL,
            source_type TEXT NOT NULL,
            collector_name TEXT NOT NULL,
            collector_version TEXT NOT NULL,
            account_id TEXT,
            region TEXT,
            resource_type TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            resource_arn TEXT,
            collected_at TEXT NOT NULL,
            observed_at TEXT,
            source_created_at TEXT,
            source_updated_at TEXT,
            canonicalization_algorithm TEXT NOT NULL,
            canonicalization_version TEXT NOT NULL,
            hash_algorithm TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL,
            previous_record_hash TEXT NOT NULL,
            record_hash TEXT NOT NULL,
            collection_status TEXT NOT NULL,
            integrity_status TEXT NOT NULL,
            freshness_status TEXT NOT NULL,
            assessment_status TEXT NOT NULL,
            provenance_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Indexes for fast querying
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_res ON evidence_records(resource_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_acct ON evidence_records(account_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence_records(source_type);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_coll ON evidence_records(collected_at);")

    # 2. Evidence Relationships Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence_relationships (
            relationship_id TEXT PRIMARY KEY,
            evidence_id TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            relationship_type TEXT NOT NULL,
            bound_payload_sha256 TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (evidence_id) REFERENCES evidence_records(evidence_id)
        );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_rel_entity ON evidence_relationships(entity_type, entity_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_rel_evidence ON evidence_relationships(evidence_id);")

    # 3. Evidence Verification Events Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence_verification_events (
            verification_id TEXT PRIMARY KEY,
            evidence_id TEXT NOT NULL,
            checked_at TEXT NOT NULL,
            integrity_status TEXT NOT NULL,
            freshness_status TEXT NOT NULL,
            verification_reason TEXT,
            verifier_version TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (evidence_id) REFERENCES evidence_records(evidence_id)
        );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_verif_evidence ON evidence_verification_events(evidence_id);")

    # 4. Triggers to enforce append-only immutability
    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS prevent_evidence_update
        BEFORE UPDATE ON evidence_records
        BEGIN
            SELECT RAISE(ABORT, 'Evidence records are immutable. Updates are forbidden.');
        END;
    """)

    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS prevent_evidence_delete
        BEFORE DELETE ON evidence_records
        BEGIN
            SELECT RAISE(ABORT, 'Evidence records are immutable. Deletions are forbidden.');
        END;
    """)

    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS prevent_rel_update
        BEFORE UPDATE ON evidence_relationships
        BEGIN
            SELECT RAISE(ABORT, 'Evidence relationships are immutable. Updates are forbidden.');
        END;
    """)

    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS prevent_rel_delete
        BEFORE DELETE ON evidence_relationships
        BEGIN
            SELECT RAISE(ABORT, 'Evidence relationships are immutable. Deletions are forbidden.');
        END;
    """)

    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS prevent_verif_update
        BEFORE UPDATE ON evidence_verification_events
        BEGIN
            SELECT RAISE(ABORT, 'Evidence verification events are immutable. Updates are forbidden.');
        END;
    """)

    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS prevent_verif_delete
        BEFORE DELETE ON evidence_verification_events
        BEGIN
            SELECT RAISE(ABORT, 'Evidence verification events are immutable. Deletions are forbidden.');
        END;
    """)

    conn.commit()
    conn.close()


class EvidenceRepository:
    """Manages CRUD operations against the persistent SQLite evidence ledger."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DB_PATH
        initialize_evidence_tables(self.db_path)

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=20.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def get_latest_record_hash(self) -> str:
        """Returns the record_hash of the most recently inserted record, or GENESIS_HASH."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT record_hash FROM evidence_records ORDER BY sequence_id DESC LIMIT 1"
            ).fetchone()
            if row:
                return row["record_hash"]
            return GENESIS_HASH
        finally:
            conn.close()

    def store_evidence_record(self, record: EvidenceRecord) -> EvidenceRecord:
        """
        Appends an evidence record to the ledger within an immediate transaction.
        Computes payload digest and record hash chained to previous record hash.
        """
        conn = self._get_connection()
        try:
            # Begin immediate transaction for serializable hash chain insertion
            conn.execute("BEGIN IMMEDIATE;")

            # 1. Determine previous record hash
            row = conn.execute(
                "SELECT record_hash FROM evidence_records ORDER BY sequence_id DESC LIMIT 1"
            ).fetchone()
            prev_hash = row["record_hash"] if row else GENESIS_HASH
            record.previous_record_hash = prev_hash

            # 2. Canonicalize payload and compute payload SHA-256
            payload_data = {
                "raw_evidence": record.raw_evidence,
                "normalized_evidence": record.normalized_evidence
            }
            canonical_payload_json = canonicalize_json_str(payload_data)
            record.payload_sha256 = compute_payload_digest(payload_data)

            # 3. Compute tamper-evident record hash
            record_dict = record.to_dict()
            record.record_hash = compute_record_hash(record_dict, prev_hash)

            prov_json = json.dumps(record.provenance.to_dict())

            # 4. Insert into database
            cursor = conn.execute("""
                INSERT INTO evidence_records (
                    evidence_id, schema_version, source_mode, source_provider, source_service,
                    source_type, collector_name, collector_version, account_id, region,
                    resource_type, resource_id, resource_arn, collected_at, observed_at,
                    source_created_at, source_updated_at, canonicalization_algorithm,
                    canonicalization_version, hash_algorithm, payload_json, payload_sha256,
                    previous_record_hash, record_hash, collection_status, integrity_status,
                    freshness_status, assessment_status, provenance_json
                ) VALUES (
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?
                );
            """, (
                record.evidence_id, record.schema_version, record.source_mode,
                record.source_provider, record.source_service, record.source_type,
                record.collector_name, record.collector_version, record.account_id,
                record.region, record.resource_type, record.resource_id, record.resource_arn,
                record.collected_at, record.observed_at, record.source_created_at,
                record.source_updated_at, record.canonicalization_algorithm,
                record.canonicalization_version, record.hash_algorithm,
                canonical_payload_json, record.payload_sha256, record.previous_record_hash,
                record.record_hash, record.collection_status, record.integrity_status,
                record.freshness_status, record.assessment_status, prov_json
            ))

            record.sequence_id = cursor.lastrowid
            conn.commit()
            return record

        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_evidence_by_id(self, evidence_id: str) -> Optional[EvidenceRecord]:
        """Retrieves an evidence record by unique ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM evidence_records WHERE evidence_id = ?",
                (evidence_id,)
            ).fetchone()
            if not row:
                return None
            return self._row_to_record(row)
        finally:
            conn.close()

    def list_evidence_records(
        self,
        limit: int = 100,
        offset: int = 0,
        source_mode: Optional[str] = None,
        resource_id: Optional[str] = None
    ) -> List[EvidenceRecord]:
        """Lists evidence records with pagination and optional filtering."""
        conn = self._get_connection()
        try:
            query = "SELECT * FROM evidence_records WHERE 1=1"
            params: List[Any] = []
            if source_mode:
                query += " AND source_mode = ?"
                params.append(source_mode)
            if resource_id:
                query += " AND resource_id = ?"
                params.append(resource_id)

            query += " ORDER BY sequence_id ASC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            rows = conn.execute(query, params).fetchall()
            return [self._row_to_record(r) for r in rows]
        finally:
            conn.close()

    def count_evidence_records(self) -> int:
        """Returns the total number of evidence records in the ledger."""
        conn = self._get_connection()
        try:
            row = conn.execute("SELECT count(*) as cnt FROM evidence_records").fetchone()
            return row["cnt"] if row else 0
        finally:
            conn.close()

    def store_relationship(self, rel: EvidenceRelationship) -> EvidenceRelationship:
        """Stores a relationship binding evidence to a finding, proposal, or rule."""
        conn = self._get_connection()
        try:
            conn.execute("""
                INSERT INTO evidence_relationships (
                    relationship_id, evidence_id, entity_type, entity_id,
                    relationship_type, bound_payload_sha256
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                rel.relationship_id, rel.evidence_id, rel.entity_type,
                rel.entity_id, rel.relationship_type, rel.bound_payload_sha256
            ))
            conn.commit()
            return rel
        finally:
            conn.close()

    def get_relationships_for_evidence(self, evidence_id: str) -> List[EvidenceRelationship]:
        """Returns all relationships associated with an evidence record."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM evidence_relationships WHERE evidence_id = ? ORDER BY created_at ASC",
                (evidence_id,)
            ).fetchall()
            return [
                EvidenceRelationship(
                    relationship_id=r["relationship_id"],
                    evidence_id=r["evidence_id"],
                    entity_type=r["entity_type"],
                    entity_id=r["entity_id"],
                    relationship_type=r["relationship_type"],
                    bound_payload_sha256=r["bound_payload_sha256"],
                    created_at=r["created_at"]
                )
                for r in rows
            ]
        finally:
            conn.close()

    def get_relationships_for_entity(self, entity_type: str, entity_id: str) -> List[EvidenceRelationship]:
        """Returns all evidence relationships for a given entity (e.g. proposal or finding)."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM evidence_relationships WHERE entity_type = ? AND entity_id = ?",
                (entity_type, entity_id)
            ).fetchall()
            return [
                EvidenceRelationship(
                    relationship_id=r["relationship_id"],
                    evidence_id=r["evidence_id"],
                    entity_type=r["entity_type"],
                    entity_id=r["entity_id"],
                    relationship_type=r["relationship_type"],
                    bound_payload_sha256=r["bound_payload_sha256"],
                    created_at=r["created_at"]
                )
                for r in rows
            ]
        finally:
            conn.close()

    def store_verification_event(self, ev: EvidenceVerificationEvent) -> EvidenceVerificationEvent:
        """Appends an evidence verification event."""
        conn = self._get_connection()
        try:
            conn.execute("""
                INSERT INTO evidence_verification_events (
                    verification_id, evidence_id, checked_at, integrity_status,
                    freshness_status, verification_reason, verifier_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                ev.verification_id, ev.evidence_id, ev.checked_at,
                ev.integrity_status, ev.freshness_status,
                ev.verification_reason, ev.verifier_version
            ))
            conn.commit()
            return ev
        finally:
            conn.close()

    def list_verification_events(self, evidence_id: str) -> List[EvidenceVerificationEvent]:
        """Lists historical verification events for an evidence record."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM evidence_verification_events WHERE evidence_id = ? ORDER BY checked_at DESC",
                (evidence_id,)
            ).fetchall()
            return [
                EvidenceVerificationEvent(
                    verification_id=r["verification_id"],
                    evidence_id=r["evidence_id"],
                    checked_at=r["checked_at"],
                    integrity_status=r["integrity_status"],
                    freshness_status=r["freshness_status"],
                    verification_reason=r["verification_reason"],
                    verifier_version=r["verifier_version"]
                )
                for r in rows
            ]
        finally:
            conn.close()

    def _row_to_record(self, row: sqlite3.Row) -> EvidenceRecord:
        payload_data = json.loads(row["payload_json"])
        prov_dict = json.loads(row["provenance_json"]) if row["provenance_json"] else {}
        prov_obj = ProvenanceInfo.from_dict(prov_dict)

        return EvidenceRecord(
            sequence_id=row["sequence_id"],
            evidence_id=row["evidence_id"],
            schema_version=row["schema_version"],
            source_mode=row["source_mode"],
            source_provider=row["source_provider"],
            source_service=row["source_service"],
            source_type=row["source_type"],
            collector_name=row["collector_name"],
            collector_version=row["collector_version"],
            account_id=row["account_id"],
            region=row["region"],
            resource_type=row["resource_type"],
            resource_id=row["resource_id"],
            resource_arn=row["resource_arn"],
            collected_at=row["collected_at"],
            observed_at=row["observed_at"],
            source_created_at=row["source_created_at"],
            source_updated_at=row["source_updated_at"],
            canonicalization_algorithm=row["canonicalization_algorithm"],
            canonicalization_version=row["canonicalization_version"],
            hash_algorithm=row["hash_algorithm"],
            raw_evidence=payload_data.get("raw_evidence", {}),
            normalized_evidence=payload_data.get("normalized_evidence", {}),
            payload_sha256=row["payload_sha256"],
            previous_record_hash=row["previous_record_hash"],
            record_hash=row["record_hash"],
            collection_status=row["collection_status"],
            integrity_status=row["integrity_status"],
            freshness_status=row["freshness_status"],
            assessment_status=row["assessment_status"],
            provenance=prov_obj,
            created_at=row["created_at"]
        )
