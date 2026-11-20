"""
ExposureFence — Multi-Source Intelligence Orchestrator Service
Unifies ingestion, normalization, correlation, lifecycle tracking, and inventory registration
across AWS Native Connectors, AWS Security Hub, AWS Config, and Prowler.
"""

from datetime import datetime, timezone
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional

from backend.database import get_connection
from backend.intelligence.config_adapter import AWSConfigAdapter
from backend.intelligence.correlation import CorrelationEngine
from backend.intelligence.ec2_adapter import EC2Adapter
from backend.intelligence.iam_adapter import IAMAdapter
from backend.intelligence.inventory import AssetInventoryRepository, initialize_inventory_tables
from backend.intelligence.lifecycle import FindingLifecycleManager
from backend.intelligence.models import AssetRecord, CanonicalFinding, FindingSeverity, FindingSource, FindingStatus
from backend.intelligence.normalization import compute_raw_hash
from backend.intelligence.prowler_adapter import ProwlerAdapter
from backend.intelligence.s3_adapter import S3Adapter
from backend.intelligence.securityhub_adapter import SecurityHubAdapter


def initialize_findings_table(db_path: Optional[str] = None) -> None:
    """Creates canonical findings table and indices."""
    conn = get_connection(db_path)
    with conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS canonical_findings (
            finding_id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            source_type TEXT NOT NULL,
            raw_finding_hash TEXT NOT NULL,
            resource_arn TEXT NOT NULL,
            account_id TEXT NOT NULL,
            region TEXT NOT NULL,
            service TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            suppression_reason TEXT,
            suppressed_until TEXT,
            evidence_id TEXT,
            correlation_id TEXT,
            raw_payload_json TEXT,
            remediation_recommendation TEXT,
            compliance_tags_json TEXT
        )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cf_resource ON canonical_findings(resource_arn)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cf_severity ON canonical_findings(severity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cf_status ON canonical_findings(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cf_correlation ON canonical_findings(correlation_id)")
    conn.close()


class MultiSourceIntelligenceService:
    """
    Central orchestration service for Multi-Source Cloud Security Intelligence.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        initialize_findings_table(db_path)
        initialize_inventory_tables(db_path)
        self.inventory = AssetInventoryRepository(db_path=db_path)

    def ingest_all_sources(self, data_mode: str = "mock") -> List[CanonicalFinding]:
        """
        Ingests findings from all 6 sources (Native S3, EC2, IAM, Security Hub, Config, Prowler).
        """
        all_raw_findings: List[CanonicalFinding] = []

        # 1. Native S3
        all_raw_findings.extend(S3Adapter.load_from_fixture())

        # 2. Native EC2 SG
        all_raw_findings.extend(EC2Adapter.load_from_fixture())

        # 3. Native IAM (from mock fixture representation)
        mock_iam_record = {
            "resource_id": "EC2WorkloadAdminRole",
            "role_name": "EC2WorkloadAdminRole",
            "has_administrator_access": True,
            "attached_policies": [{"policy_name": "AdministratorAccess", "is_admin_policy": True}]
        }
        iam_finding = IAMAdapter.from_record(mock_iam_record)
        if iam_finding:
            all_raw_findings.append(iam_finding)

        # 4. AWS Security Hub
        all_raw_findings.extend(SecurityHubAdapter.load_from_fixture())

        # 5. AWS Config Compliance
        all_raw_findings.extend(AWSConfigAdapter.load_from_fixture())

        # 6. Prowler
        all_raw_findings.extend(ProwlerAdapter.load_from_fixture())

        # Deduplicate and correlate
        deduped = CorrelationEngine.deduplicate(all_raw_findings)
        correlated = CorrelationEngine.correlate_findings(deduped)

        # Register in SQLite database and asset inventory
        for fnd in correlated:
            self.save_finding(fnd)
            self._register_asset_from_finding(fnd)

        return correlated

    def _register_asset_from_finding(self, finding: CanonicalFinding) -> None:
        """Registers the asset in the inventory."""
        res_id = finding.resource_arn.split(":")[-1].split("/")[-1]
        config_digest = compute_raw_hash(finding.raw_payload or finding.resource_arn)

        asset = AssetRecord(
            resource_arn=finding.resource_arn,
            account_id=finding.account_id,
            region=finding.region,
            service=finding.service,
            resource_type=finding.resource_type,
            resource_id=res_id,
            configuration_digest=config_digest,
            last_scanned=datetime.now(timezone.utc).isoformat(),
            metadata={"source": finding.source_type.value}
        )
        self.inventory.register_asset(asset)

    def save_finding(self, finding: CanonicalFinding) -> CanonicalFinding:
        """Persists a CanonicalFinding to SQLite."""
        conn = get_connection(self.db_path)
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO canonical_findings (
                        finding_id, source_id, source_type, raw_finding_hash,
                        resource_arn, account_id, region, service, resource_type,
                        title, description, severity, status, first_seen, last_seen,
                        suppression_reason, suppressed_until, evidence_id,
                        correlation_id, raw_payload_json, remediation_recommendation,
                        compliance_tags_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(finding_id) DO UPDATE SET
                        status = excluded.status,
                        last_seen = excluded.last_seen,
                        correlation_id = excluded.correlation_id,
                        compliance_tags_json = excluded.compliance_tags_json,
                        suppression_reason = excluded.suppression_reason,
                        suppressed_until = excluded.suppressed_until
                    """,
                    (
                        finding.finding_id,
                        finding.source_id,
                        finding.source_type.value,
                        finding.raw_finding_hash,
                        finding.resource_arn,
                        finding.account_id,
                        finding.region,
                        finding.service,
                        finding.resource_type,
                        finding.title,
                        finding.description,
                        finding.severity.value,
                        finding.status.value,
                        finding.first_seen,
                        finding.last_seen,
                        finding.suppression_reason,
                        finding.suppressed_until,
                        finding.evidence_id,
                        finding.correlation_id,
                        json.dumps(finding.raw_payload),
                        finding.remediation_recommendation,
                        json.dumps(finding.compliance_tags)
                    )
                )
        finally:
            conn.close()
        return finding

    def get_finding(self, finding_id: str) -> Optional[CanonicalFinding]:
        """Retrieves a single finding by ID."""
        conn = get_connection(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM canonical_findings WHERE finding_id = ?", (finding_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_finding(row)
        finally:
            conn.close()

    def list_findings(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        service: Optional[str] = None,
        resource_arn: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> List[CanonicalFinding]:
        """Lists findings with optional filtering."""
        conn = get_connection(self.db_path)
        try:
            cursor = conn.cursor()
            query = "SELECT * FROM canonical_findings WHERE 1=1"
            params: List[Any] = []
            if severity:
                query += " AND severity = ?"
                params.append(severity.upper())
            if status:
                query += " AND status = ?"
                params.append(status.upper())
            if service:
                query += " AND service = ?"
                params.append(service.lower())
            if resource_arn:
                query += " AND resource_arn = ?"
                params.append(resource_arn)
            if correlation_id:
                query += " AND correlation_id = ?"
                params.append(correlation_id)

            query += " ORDER BY last_seen DESC"
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [self._row_to_finding(r) for r in rows]
        finally:
            conn.close()

    def suppress_finding(self, finding_id: str, justification: str, suppressed_until: str, approver: str = "security-admin") -> Optional[CanonicalFinding]:
        """Suppresses a finding with mandatory justification."""
        fnd = self.get_finding(finding_id)
        if not fnd:
            return None
        FindingLifecycleManager.suppress(fnd, justification, suppressed_until, approver=approver)
        return self.save_finding(fnd)

    def _row_to_finding(self, row: Any) -> CanonicalFinding:
        return CanonicalFinding(
            finding_id=row[0],
            source_id=row[1],
            source_type=FindingSource(row[2]),
            raw_finding_hash=row[3],
            resource_arn=row[4],
            account_id=row[5],
            region=row[6],
            service=row[7],
            resource_type=row[8],
            title=row[9],
            description=row[10],
            severity=FindingSeverity(row[11]),
            status=FindingStatus(row[12]),
            first_seen=row[13],
            last_seen=row[14],
            suppression_reason=row[15],
            suppressed_until=row[16],
            evidence_id=row[17],
            correlation_id=row[18],
            raw_payload=json.loads(row[19]) if row[19] else {},
            remediation_recommendation=row[20],
            compliance_tags=json.loads(row[21]) if row[21] else []
        )
