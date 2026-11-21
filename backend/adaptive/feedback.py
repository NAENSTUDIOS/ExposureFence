"""
ExposureFence — Continuous Learning & Feedback Store
Records outcomes of adaptations, false positives, reviewer rejections,
and verified mitigations to continuously improve solution ranking.
"""

from typing import Dict, List
import uuid

from backend.adaptive.models import FeedbackRecord


class AdaptiveFeedbackStore:
    """Stores outcomes and human feedback for the ASIVE learning cycle."""

    def __init__(self):
        self._feedback_records: Dict[str, FeedbackRecord] = {}

    def record_feedback(
        self,
        solution_id: str,
        outcome: str,
        human_notes: str = "",
        false_positive: bool = False,
        regression_observed: bool = False
    ) -> FeedbackRecord:
        record_id = f"FDB-{uuid.uuid4().hex[:8]}"
        record = FeedbackRecord(
            feedback_id=record_id,
            solution_id=solution_id,
            outcome=outcome,
            human_notes=human_notes,
            false_positive=false_positive,
            regression_observed=regression_observed
        )
        self._feedback_records[record_id] = record
        return record

    def list_feedback(self) -> List[FeedbackRecord]:
        return list(self._feedback_records.values())
