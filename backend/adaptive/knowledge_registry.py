"""
ExposureFence — Versioned Security Knowledge Registry
Tracks evolving security knowledge, source versions, provenance hashes,
and rollback capabilities. Supports reproducible historical security evaluations.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional
import uuid

from backend.adaptive.models import KnowledgeRecord


class KnowledgeRegistry:
    """Manages versioned, provenance-backed security knowledge."""

    def __init__(self):
        self._registry: Dict[str, KnowledgeRecord] = {}
        self._seed_default_knowledge()

    def _seed_default_knowledge(self) -> None:
        """Seeds baseline security knowledge records."""
        k1 = KnowledgeRecord(
            knowledge_id="KNW-CIS-AWS-3.0",
            version="3.0.0",
            title="CIS AWS Foundations Benchmark v3.0 Baseline",
            domain="COMPLIANCE",
            source_id="CIS_OFFICIAL",
            effective_date="2026-01-01T00:00:00Z",
            review_date="2026-12-31T00:00:00Z",
            confidence=1.0,
            evidence_hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            affected_controls=["CIS-1.16", "CIS-2.1.5", "CIS-5.1"],
            adoption_status="ADOPTED"
        )
        self._registry[k1.knowledge_id] = k1

    def register_knowledge(self, record: KnowledgeRecord) -> KnowledgeRecord:
        """Registers or updates a versioned knowledge item."""
        self._registry[record.knowledge_id] = record
        return record

    def get_knowledge(self, knowledge_id: str) -> Optional[KnowledgeRecord]:
        return self._registry.get(knowledge_id)

    def list_knowledge(self, domain: Optional[str] = None) -> List[KnowledgeRecord]:
        items = list(self._registry.values())
        if domain:
            items = [i for i in items if i.domain == domain]
        return items
