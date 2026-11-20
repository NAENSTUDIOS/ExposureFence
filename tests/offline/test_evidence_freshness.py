"""
Tests for Evidence Freshness Module
Validates freshness policies, clock-skew boundaries, stale evidence detection,
and distinction between synthetic static fixtures and live cloud observations.
"""

from datetime import datetime, timedelta, timezone
import pytest

from backend.evidence.exceptions import EvidenceFreshnessError
from backend.evidence.freshness import (
    evaluate_freshness,
    get_evidence_age_seconds,
    is_evidence_stale,
)
from backend.evidence.models import EvidenceRecord, FreshnessStatus, SourceMode


def test_static_mock_fixture_freshness():
    """Synthetic mock fixtures are always classified as STATIC_FIXTURE, never STALE."""
    rec = EvidenceRecord(
        evidence_id="EV-STATIC-001",
        source_mode=SourceMode.MOCK.value,
        collected_at="2020-01-01T00:00:00Z"  # very old timestamp
    )

    status = evaluate_freshness(rec)
    assert status == FreshnessStatus.STATIC_FIXTURE
    assert is_evidence_stale(rec) is False


def test_live_fresh_evidence():
    """Live evidence collected 5 minutes ago is FRESH under a 1-hour policy."""
    now = datetime.now(timezone.utc)
    collected = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")

    rec = EvidenceRecord(
        evidence_id="EV-LIVE-FRESH",
        source_mode=SourceMode.AWS_READ_ONLY.value,
        source_type="AWS::S3::Bucket",
        collected_at=collected
    )

    status = evaluate_freshness(rec, max_age_seconds=3600, current_time=now)
    assert status == FreshnessStatus.FRESH
    assert is_evidence_stale(rec, max_age_seconds=3600, current_time=now) is False


def test_live_stale_evidence():
    """Live evidence collected 2 hours ago is STALE under a 1-hour policy."""
    now = datetime.now(timezone.utc)
    collected = (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

    rec = EvidenceRecord(
        evidence_id="EV-LIVE-STALE",
        source_mode=SourceMode.AWS_READ_ONLY.value,
        source_type="AWS::S3::Bucket",
        collected_at=collected
    )

    status = evaluate_freshness(rec, max_age_seconds=3600, current_time=now)
    assert status == FreshnessStatus.STALE
    assert is_evidence_stale(rec, max_age_seconds=3600, current_time=now) is True


def test_future_timestamp_clock_skew_rejection():
    """Timestamp in the future beyond 300 seconds raises EvidenceFreshnessError."""
    now = datetime.now(timezone.utc)
    future_time = (now + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")

    rec = EvidenceRecord(
        evidence_id="EV-FUTURE",
        source_mode=SourceMode.AWS_READ_ONLY.value,
        source_type="AWS::S3::Bucket",
        collected_at=future_time
    )

    with pytest.raises(EvidenceFreshnessError, match="future beyond allowed clock skew"):
        evaluate_freshness(rec, current_time=now)


def test_missing_timestamp_returns_unknown():
    """Live record with no collected_at returns UNKNOWN."""
    rec = EvidenceRecord(
        evidence_id="EV-UNKNOWN",
        source_mode=SourceMode.AWS_READ_ONLY.value,
        source_type="AWS::S3::Bucket",
        collected_at=""
    )

    status = evaluate_freshness(rec)
    assert status == FreshnessStatus.UNKNOWN
