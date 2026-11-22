"""
ExposureFence — Region & Assessment Request Budget Boundaries
Enforces region allowlists, API call budgeting, rate limiting, and backoff pacing.
"""

import os
import random
import re
import threading
import time
from typing import List, Optional, Set

from backend.connectors.exceptions import (
    APIBudgetExceededError,
    APIRateLimitExceededError,
    UnauthorizedRegionError
)

DEFAULT_ALLOWED_REGIONS: List[str] = ["us-east-1"]
GLOBAL_SERVICES: Set[str] = {"iam", "sts", "route53", "cloudfront"}
REGION_FORMAT_REGEX = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d+$")

DEFAULT_API_CALL_BUDGET = 200
MAX_SAFE_API_BUDGET = 1000
DEFAULT_MAX_CALLS_PER_SECOND = 5.0


def get_allowed_regions() -> List[str]:
    """
    Parses and validates configured allowed regions from EXPOSUREFENCE_ALLOWED_REGIONS.
    Defaults to ['us-east-1'].
    """
    raw = os.getenv("EXPOSUREFENCE_ALLOWED_REGIONS", "").strip()
    if not raw:
        return list(DEFAULT_ALLOWED_REGIONS)

    regions = [r.strip().lower() for r in raw.split(",") if r.strip()]
    validated = []
    for r in regions:
        if not REGION_FORMAT_REGEX.match(r):
            raise UnauthorizedRegionError(f"Invalid region format in allowlist: '{r}'")
        validated.append(r)

    if not validated:
        return list(DEFAULT_ALLOWED_REGIONS)
    return validated


def validate_region(region: Optional[str], service_name: Optional[str] = None) -> str:
    """
    Validates whether a target region is authorized.
    Global services (IAM, STS) resolve cleanly to 'us-east-1' when specified as 'global' or omitted.
    """
    target = (region or "").strip().lower()
    allowed = get_allowed_regions()

    # Handle global services
    if service_name and service_name.lower() in GLOBAL_SERVICES:
        if not target or target in ("global", "us-east-1"):
            return "us-east-1"

    # Regional service resolution
    if not target:
        return allowed[0]

    if target not in allowed:
        raise UnauthorizedRegionError(
            f"Target region '{target}' is not in the configured region allowlist: {allowed}"
        )

    return target


class APICallBudget:
    """
    Assessment-level API call budget manager.
    Tracks total calls made and bounded retries, rejecting calls when budget is exhausted.
    """

    def __init__(self, max_budget: Optional[int] = None):
        configured = int(os.getenv("EXPOSUREFENCE_API_CALL_BUDGET", str(DEFAULT_API_CALL_BUDGET)))
        self.max_budget = min(max_budget or configured, MAX_SAFE_API_BUDGET)
        self.current_calls = 0
        self._lock = threading.Lock()

    def record_call(self, count: int = 1) -> int:
        """Records API calls against the budget. Raises APIBudgetExceededError if exhausted."""
        with self._lock:
            if self.current_calls + count > self.max_budget:
                raise APIBudgetExceededError(
                    f"Assessment API call budget exceeded: attempted {self.current_calls + count} calls (limit: {self.max_budget})."
                )
            self.current_calls += count
            return self.current_calls

    def remaining_budget(self) -> int:
        """Returns the number of remaining authorized API calls."""
        with self._lock:
            return max(0, self.max_budget - self.current_calls)

    def reset(self) -> None:
        """Resets the assessment call counter."""
        with self._lock:
            self.current_calls = 0


class RateLimiter:
    """
    Enforces maximum request rate (default <= 5 calls/sec) and jittered exponential backoff.
    """

    def __init__(self, max_calls_per_second: Optional[float] = None):
        configured = float(os.getenv("EXPOSUREFENCE_MAX_CALLS_PER_SECOND", str(DEFAULT_MAX_CALLS_PER_SECOND)))
        self.max_calls_per_second = max(0.1, min(max_calls_per_second or configured, 20.0))
        self.min_interval = 1.0 / self.max_calls_per_second
        self.last_call_time = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Paces execution to ensure request rate does not exceed allowed threshold."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_call_time
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_call_time = time.monotonic()

    @staticmethod
    def compute_backoff(attempt: int, base_delay: float = 0.2, max_delay: float = 4.0) -> float:
        """Calculates bounded exponential backoff with full jitter."""
        temp = min(max_delay, base_delay * (2 ** attempt))
        return random.uniform(0, temp)
