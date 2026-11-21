"""
ExposureFence — Continuous Observation Engine
Monitors changes across Cloud Security, Vulnerabilities, AI Security, Compliance,
and Project Health. Operates offline-first using validated local fixtures with zero cloud cost.
"""

from datetime import datetime, timezone
import json
import os
from typing import Dict, List, Optional

from backend.adaptive.models import CloudProvider, ObservationRecord, ObservationSourceType


DEFAULT_OBSERVATIONS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "mock_data",
    "adaptive",
    "observations.json"
)


class ContinuousObservationEngine:
    """
    Extensible observer for continuous threat, vulnerability, and platform intelligence.
    Loads and normalizes multi-source observations from offline fixtures or verified adapters.
    """

    def __init__(self, fixtures_path: Optional[str] = None):
        self.fixtures_path = fixtures_path or DEFAULT_OBSERVATIONS_PATH
        self._observations: Dict[str, ObservationRecord] = {}
        self.reload_observations()

    def reload_observations(self) -> None:
        """Loads and parses observation records."""
        self._observations.clear()
        if not os.path.exists(self.fixtures_path):
            return

        try:
            with open(self.fixtures_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data:
                    record = ObservationRecord(
                        id=item["id"],
                        source_type=ObservationSourceType(item["source_type"]),
                        source_name=item["source_name"],
                        timestamp=item["timestamp"],
                        source_version=item.get("source_version", "1.0"),
                        evidence_ref=item.get("evidence_ref", ""),
                        payload=item.get("payload", {}),
                        confidence=item.get("confidence", 1.0),
                        relevance=item.get("relevance", 1.0),
                        freshness=item.get("freshness", "FRESH"),
                        validation_status=item.get("validation_status", "VALIDATED"),
                        provider=CloudProvider(item.get("provider", "AWS"))
                    )
                    self._observations[record.id] = record
        except Exception:
            pass

    def list_observations(
        self,
        source_type: Optional[ObservationSourceType] = None,
        provider: Optional[CloudProvider] = None
    ) -> List[ObservationRecord]:
        """Returns filtered observations."""
        records = list(self._observations.values())
        if source_type:
            records = [r for r in records if r.source_type == source_type]
        if provider:
            records = [r for r in records if r.provider == provider]
        return records

    def ingest_observation(self, observation: ObservationRecord) -> ObservationRecord:
        """Ingests an observation record in memory."""
        self._observations[observation.id] = observation
        return observation
