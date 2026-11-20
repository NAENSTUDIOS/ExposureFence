"""
ExposureFence — Cloud Asset Inventory & Configuration Drift Repository
Maintains the centralized inventory of discovered cloud resources, tracks configuration
digests using RFC 8785 canonical hashes, and detects unapproved infrastructure drift.
"""

from datetime import datetime, timezone
import json
import sqlite3
from typing import Any, Dict, List, Optional

from backend.database import get_connection
from backend.intelligence.models import AssetRecord


def initialize_inventory_tables(db_path: Optional[str] = None) -> None:
    """Creates asset inventory tables and indices if not present."""
    conn = get_connection(db_path)
    with conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS cloud_asset_inventory (
            resource_arn TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            region TEXT NOT NULL,
            service TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            tags_json TEXT,
            configuration_digest TEXT NOT NULL,
            last_scanned TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            drift_detected INTEGER DEFAULT 0,
            metadata_json TEXT
        )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_asset_service ON cloud_asset_inventory(service)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_asset_account ON cloud_asset_inventory(account_id)")
    conn.close()


class AssetInventoryRepository:
    """Repository managing cloud asset state and configuration drift detection."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        initialize_inventory_tables(db_path)

    def register_asset(self, asset: AssetRecord) -> AssetRecord:
        """
        Registers or updates an asset in the inventory.
        Detects configuration drift if the new configuration_digest differs from previous.
        """
        conn = get_connection(self.db_path)
        drift = False

        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT configuration_digest FROM cloud_asset_inventory WHERE resource_arn = ?",
                (asset.resource_arn,)
            )
            row = cursor.fetchone()

            if row:
                old_digest = row[0]
                if old_digest and asset.configuration_digest and old_digest != asset.configuration_digest:
                    drift = True
                    asset.drift_detected = True
                    try:
                        from backend.audit import log_event
                        log_event(
                            "ASSET_CONFIGURATION_DRIFT",
                            {
                                "resource_arn": asset.resource_arn,
                                "old_digest": old_digest,
                                "new_digest": asset.configuration_digest,
                                "service": asset.service
                            }
                        )
                    except Exception:
                        pass
                else:
                    asset.drift_detected = False

            with conn:
                conn.execute(
                    """
                    INSERT INTO cloud_asset_inventory (
                        resource_arn, account_id, region, service, resource_type,
                        resource_id, tags_json, configuration_digest, last_scanned,
                        is_active, drift_detected, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(resource_arn) DO UPDATE SET
                        account_id = excluded.account_id,
                        region = excluded.region,
                        service = excluded.service,
                        resource_type = excluded.resource_type,
                        resource_id = excluded.resource_id,
                        tags_json = excluded.tags_json,
                        configuration_digest = excluded.configuration_digest,
                        last_scanned = excluded.last_scanned,
                        is_active = excluded.is_active,
                        drift_detected = excluded.drift_detected,
                        metadata_json = excluded.metadata_json
                    """,
                    (
                        asset.resource_arn,
                        asset.account_id,
                        asset.region,
                        asset.service,
                        asset.resource_type,
                        asset.resource_id,
                        json.dumps(asset.tags),
                        asset.configuration_digest,
                        asset.last_scanned,
                        1 if asset.is_active else 0,
                        1 if asset.drift_detected else 0,
                        json.dumps(asset.metadata),
                    )
                )
        finally:
            conn.close()

        return asset

    def get_asset(self, resource_arn: str) -> Optional[AssetRecord]:
        """Retrieves a single asset by ARN."""
        conn = get_connection(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT resource_arn, account_id, region, service, resource_type,
                       resource_id, tags_json, configuration_digest, last_scanned,
                       is_active, drift_detected, metadata_json
                FROM cloud_asset_inventory WHERE resource_arn = ?
                """,
                (resource_arn,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return AssetRecord(
                resource_arn=row[0],
                account_id=row[1],
                region=row[2],
                service=row[3],
                resource_type=row[4],
                resource_id=row[5],
                tags=json.loads(row[6]) if row[6] else {},
                configuration_digest=row[7],
                last_scanned=row[8],
                is_active=bool(row[9]),
                drift_detected=bool(row[10]),
                metadata=json.loads(row[11]) if row[11] else {}
            )
        finally:
            conn.close()

    def list_assets(
        self,
        service: Optional[str] = None,
        account_id: Optional[str] = None,
        drift_only: bool = False
    ) -> List[AssetRecord]:
        """Lists assets with optional service, account, and drift filtering."""
        conn = get_connection(self.db_path)
        try:
            cursor = conn.cursor()
            query = """
                SELECT resource_arn, account_id, region, service, resource_type,
                       resource_id, tags_json, configuration_digest, last_scanned,
                       is_active, drift_detected, metadata_json
                FROM cloud_asset_inventory WHERE 1=1
            """
            params: List[Any] = []
            if service:
                query += " AND service = ?"
                params.append(service.lower())
            if account_id:
                query += " AND account_id = ?"
                params.append(account_id)
            if drift_only:
                query += " AND drift_detected = 1"

            query += " ORDER BY last_scanned DESC"
            cursor.execute(query, params)
            rows = cursor.fetchall()

            assets = []
            for row in rows:
                assets.append(AssetRecord(
                    resource_arn=row[0],
                    account_id=row[1],
                    region=row[2],
                    service=row[3],
                    resource_type=row[4],
                    resource_id=row[5],
                    tags=json.loads(row[6]) if row[6] else {},
                    configuration_digest=row[7],
                    last_scanned=row[8],
                    is_active=bool(row[9]),
                    drift_detected=bool(row[10]),
                    metadata=json.loads(row[11]) if row[11] else {}
                ))
            return assets
        finally:
            conn.close()
