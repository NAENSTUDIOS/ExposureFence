"""
ExposureFence Evidence Engine Freshness Module
Evaluates evidence freshness, clock-skew boundaries, and source-specific retention policies.
Integrity and Freshness are distinct: a perfectly verified record may still be stale.
"""

from datetime import datetime, timezone
from typing import Dict, Optional

from backend.evidence.exceptions import EvidenceFreshnessError
from backend.evidence.models import EvidenceRecord, FreshnessStatus, SourceMode

# Default max age policies in seconds
DEFAULT_FRESHNESS_POLICIES: Dict[str, int] = {
    "AWS::S3::Bucket": 3600,            # 1 hour
    "AWS::EC2::SecurityGroup": 1800,     # 30 minutes
    "AWS::IAM::Role": 86400,             # 24 hours
    "DEFAULT": 3600                      # 1 hour default for other live AWS assets
}

MAX_ALLOWED_CLOCK_SKEW_SECONDS = 300  # 5 minutes


def parse_iso8601_utc(dt_str: str) -> datetime:
    """Parses an ISO-8601 string and ensures it is timezone-aware UTC."""
    if not dt_str or not isinstance(dt_str, str):
        raise EvidenceFreshnessError(f"Missing or non-string timestamp: {dt_str}")
    try:
        clean = dt_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception as e:
        raise EvidenceFreshnessError(f"Invalid ISO-8601 timestamp '{dt_str}': {e}") from e


def get_evidence_age_seconds(record: EvidenceRecord, current_time: Optional[datetime] = None) -> Optional[float]:
    """
    Computes the age of an evidence record in seconds based on its collection or observation time.
    Returns None if timestamp is missing or record is a static fixture.
    """
    if record.source_mode == SourceMode.MOCK.value:
        return None

    ref_time_str = record.observed_at or record.collected_at
    if not ref_time_str:
        return None

    ref_dt = parse_iso8601_utc(ref_time_str)
    now = current_time or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    # Check clock skew (future timestamp)
    age = (now - ref_dt).total_seconds()
    if age < -MAX_ALLOWED_CLOCK_SKEW_SECONDS:
        raise EvidenceFreshnessError(
            f"Evidence timestamp is in the future beyond allowed clock skew: {age}s ahead of system time"
        )

    return max(0.0, age)


def evaluate_freshness(
    record: EvidenceRecord,
    max_age_seconds: Optional[int] = None,
    current_time: Optional[datetime] = None
) -> FreshnessStatus:
    """
    Evaluates evidence freshness status:
      - STATIC_FIXTURE: For synthetic mock fixtures
      - FRESH: Live evidence within max_age_seconds
      - STALE: Live evidence older than max_age_seconds
      - UNKNOWN: Missing or unparseable time information
    """
    # 1. Static fixtures are permanently categorized as STATIC_FIXTURE
    if record.source_mode == SourceMode.MOCK.value:
        return FreshnessStatus.STATIC_FIXTURE

    ref_time_str = record.observed_at or record.collected_at
    if not ref_time_str:
        return FreshnessStatus.UNKNOWN

    try:
        age_seconds = get_evidence_age_seconds(record, current_time=current_time)
        if age_seconds is None:
            return FreshnessStatus.UNKNOWN

        allowed_max_age = max_age_seconds
        if allowed_max_age is None:
            allowed_max_age = DEFAULT_FRESHNESS_POLICIES.get(
                record.source_type,
                DEFAULT_FRESHNESS_POLICIES["DEFAULT"]
            )

        if age_seconds <= allowed_max_age:
            return FreshnessStatus.FRESH
        return FreshnessStatus.STALE

    except EvidenceFreshnessError:
        raise
    except Exception:
        return FreshnessStatus.UNKNOWN


def is_evidence_stale(
    record: EvidenceRecord,
    max_age_seconds: Optional[int] = None,
    current_time: Optional[datetime] = None
) -> bool:
    """Returns True ONLY if live AWS evidence is older than its configured max age."""
    status = evaluate_freshness(record, max_age_seconds=max_age_seconds, current_time=current_time)
    return status == FreshnessStatus.STALE
