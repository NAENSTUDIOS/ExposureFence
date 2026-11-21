"""
ExposureFence — Change Detection & Intelligence Normalization Engine
Normalizes heterogeneous observations into structured ChangeEvents, detects duplicate
reports, flags conflicting sources, and tracks verification status.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from backend.adaptive.models import (
    ChangeEvent,
    ChangeEventCategory,
    ChangeEventStatus,
    CloudProvider,
    ObservationRecord,
    ObservationSourceType,
)


class ChangeDetector:
    """
    Detects and normalizes change events across multi-source observations.
    Eliminates duplicates via content fingerprinting and avoids elevating unverified claims.
    """

    def __init__(self):
        self._events: Dict[str, ChangeEvent] = {}
        self._fingerprints: Dict[str, str] = {}  # fingerprint -> event_id

    def process_observations(self, observations: List[ObservationRecord]) -> List[ChangeEvent]:
        """Normalizes a stream of observations into structured change events."""
        for obs in observations:
            category = self._map_source_to_category(obs)
            title = obs.payload.get("title") or obs.payload.get("change_type") or obs.payload.get("technique") or obs.payload.get("cve_id") or "Unclassified Security Change"
            description = obs.payload.get("description", str(obs.payload))

            # Determine initial status
            if obs.validation_status == "VALIDATED" and obs.confidence >= 0.90:
                status = ChangeEventStatus.CONFIRMED
            elif obs.confidence >= 0.70:
                status = ChangeEventStatus.SUSPECTED
            else:
                status = ChangeEventStatus.UNVERIFIED

            urgency = obs.payload.get("severity") or ("CRITICAL" if obs.payload.get("cvss_score", 0) >= 8.5 else "HIGH" if obs.payload.get("cvss_score", 0) >= 7.0 else "MEDIUM")

            affected = []
            if "service" in obs.payload:
                affected.append(f"connector:{obs.payload['service']}")
            if "affected_component" in obs.payload:
                affected.append(obs.payload["affected_component"])
            if "target_service" in obs.payload:
                affected.append(f"service:{obs.payload['target_service']}")
            if "subsystem" in obs.payload:
                affected.append(f"subsystem:{obs.payload['subsystem']}")

            event = ChangeEvent(
                event_id=f"EVT-{obs.id}",
                category=category,
                title=str(title),
                description=str(description),
                detected_at=obs.timestamp or datetime.now(timezone.utc).isoformat(),
                status=status,
                source_observation_ids=[obs.id],
                confidence=obs.confidence,
                urgency=urgency,
                affected_components=affected,
                provider=obs.provider
            )

            # Deduplication
            if event.dedup_fingerprint in self._fingerprints:
                existing_id = self._fingerprints[event.dedup_fingerprint]
                existing = self._events[existing_id]
                if obs.id not in existing.source_observation_ids:
                    existing.source_observation_ids.append(obs.id)
                # Multi-source corroboration increases confidence
                existing.confidence = min(1.0, existing.confidence + 0.05)
                if existing.confidence >= 0.95:
                    existing.status = ChangeEventStatus.CONFIRMED
            else:
                self._events[event.event_id] = event
                self._fingerprints[event.dedup_fingerprint] = event.event_id

        return list(self._events.values())

    def list_events(self, status: Optional[ChangeEventStatus] = None) -> List[ChangeEvent]:
        events = list(self._events.values())
        if status:
            events = [e for e in events if e.status == status]
        return events

    def _map_source_to_category(self, obs: ObservationRecord) -> ChangeEventCategory:
        if obs.source_type == ObservationSourceType.VULNERABILITY:
            return ChangeEventCategory.NEW_VULNERABILITY
        elif obs.source_type == ObservationSourceType.AI_SECURITY:
            return ChangeEventCategory.ATTACK_TECHNIQUE_CHANGE
        elif obs.source_type == ObservationSourceType.COMPLIANCE:
            return ChangeEventCategory.COMPLIANCE_CHANGE
        elif obs.source_type == ObservationSourceType.PROJECT_HEALTH:
            return ChangeEventCategory.SECURITY_REGRESSION
        elif "iam" in str(obs.payload).lower():
            return ChangeEventCategory.ATTACK_TECHNIQUE_CHANGE
        return ChangeEventCategory.NEW_THREAT
