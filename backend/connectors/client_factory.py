"""
ExposureFence — Centralized Read-Only AWS Client Factory & Proxy
Enforces service-level and operation-level allowlists, timeout constraints, rate-limiting,
API call budgeting, bounded retries on throttling, and strictly rejects any mutating operations.
"""

from functools import wraps
import logging
import os
import time
from typing import Any, Callable, Dict, Optional, Set

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, ConnectTimeoutError, ReadTimeoutError

from backend.connectors.boundaries import (
    APICallBudget,
    RateLimiter,
    validate_region
)
from backend.connectors.exceptions import (
    APIBudgetExceededError,
    APITimeoutError,
    APIThrottledError,
    UnauthorizedRegionError,
    UnauthorizedServiceError,
    UnsafeCloudOperationError
)

logger = logging.getLogger("exposurefence.connectors.factory")

# Explicit Allowlist of Permitted Services
ALLOWED_SERVICES: Set[str] = {
    "s3",
    "ec2",
    "iam",
    "sts",
    "securityhub",
    "config"
}

# Explicit Allowlist of Permitted Read-Only API Operations per Service
ALLOWED_OPERATIONS: Dict[str, Set[str]] = {
    "s3": {
        "list_buckets",
        "get_public_access_block",
        "get_bucket_policy_status",
        "get_bucket_policy",
        "get_bucket_acl",
        "get_bucket_location",
        "get_bucket_encryption",
        "get_bucket_versioning",
        "get_bucket_ownership_controls"
    },
    "ec2": {
        "describe_security_groups",
        "describe_instances",
        "describe_network_interfaces",
        "describe_vpcs",
        "describe_subnets",
        "describe_route_tables"
    },
    "iam": {
        "list_roles",
        "get_role",
        "list_attached_role_policies",
        "list_role_policies",
        "get_role_policy",
        "list_users",
        "get_user",
        "list_attached_user_policies",
        "list_user_policies",
        "get_user_policy",
        "get_policy",
        "get_policy_version",
        "get_account_summary"
    },
    "sts": {
        "get_caller_identity"
    },
    "securityhub": {
        "get_findings",
        "describe_hub"
    },
    "config": {
        "get_resource_config_history",
        "get_compliance_details_by_config_rule",
        "select_resource_config",
        "describe_config_rules"
    }
}

# Operation prefixes that are strictly forbidden cloud mutations
PROHIBITED_MUTATION_PREFIXES = (
    "put_",
    "delete_",
    "create_",
    "update_",
    "modify_",
    "authorize_",
    "revoke_",
    "attach_",
    "detach_",
    "post_",
    "remove_",
    "enable_",
    "disable_",
    "tag_",
    "untag_",
    "start_",
    "stop_",
    "reboot_",
    "terminate_"
)

THROTTLING_ERROR_CODES = {
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown"
}


class ReadOnlyClientProxy:
    """
    Transparent proxy wrapping a Boto3 client to enforce read-only operation allowlists,
    budget limits, rate pacing, timeouts, and bounded retries.
    """

    def __init__(
        self,
        raw_client: Any,
        service_name: str,
        budget: Optional[APICallBudget] = None,
        rate_limiter: Optional[RateLimiter] = None
    ):
        self._raw_client = raw_client
        self._service_name = service_name.lower()
        self._budget = budget or APICallBudget()
        self._rate_limiter = rate_limiter or RateLimiter()
        self._allowed_ops = ALLOWED_OPERATIONS.get(self._service_name, set())

    def get_paginator(self, operation_name: str) -> Any:
        """Returns a paginator for an allowlisted read-only operation."""
        normalized_op = operation_name.lower().replace("-", "_")
        if normalized_op not in self._allowed_ops:
            raise UnsafeCloudOperationError(
                f"Unauthorized paginator operation: '{operation_name}' is not in the read-only allowlist for service '{self._service_name}'."
            )
        if hasattr(self._raw_client, "get_paginator"):
            return self._raw_client.get_paginator(operation_name)
        raise AttributeError(f"Client for '{self._service_name}' does not implement get_paginator.")

    def __getattr__(self, name: str) -> Any:
        # Pass through internal attributes
        if name.startswith("_"):
            return getattr(self._raw_client, name)

        normalized_name = name.lower()

        # Invariant 1: Reject any mutating operation prefix immediately
        for prefix in PROHIBITED_MUTATION_PREFIXES:
            if normalized_name.startswith(prefix):
                raise UnsafeCloudOperationError(
                    f"Prohibited mutating cloud operation: '{name}' on service '{self._service_name}' violates read-only invariant."
                )

        # Invariant 2: Operation must be on the service-specific read-only allowlist
        if normalized_name not in self._allowed_ops:
            raise UnsafeCloudOperationError(
                f"Unauthorized operation: '{name}' is not in the read-only allowlist for service '{self._service_name}'."
            )

        attr = getattr(self._raw_client, name)
        if not callable(attr):
            return attr

        @wraps(attr)
        def intercepted_call(*args, **kwargs):
            # Cost safety check before any execution (Global Free-Tier-Only Cost Safety Override)
            from backend.connectors.cost_governor import get_cost_governor
            from backend.connectors.aws_session import is_aws_mode_enabled
            cost_governor = get_cost_governor()
            is_live = is_aws_mode_enabled()
            cost_governor.verify_cost_safety(
                service=self._service_name,
                operation=normalized_name,
                expected_count=1,
                is_live=is_live
            )

            # Budget check & rate pacing before execution
            self._budget.record_call(1)
            self._rate_limiter.acquire()

            max_retries = 3
            last_err = None

            for attempt in range(max_retries):
                try:
                    return attr(*args, **kwargs)
                except (ConnectTimeoutError, ReadTimeoutError) as te:
                    raise APITimeoutError(
                        f"AWS API call '{name}' timed out after configured threshold: {te}"
                    ) from te
                except ClientError as ce:
                    error_code = ce.response.get("Error", {}).get("Code", "")
                    if error_code in THROTTLING_ERROR_CODES:
                        last_err = ce
                        if attempt < max_retries - 1:
                            # Retries count toward the budget
                            self._budget.record_call(1)
                            backoff = RateLimiter.compute_backoff(attempt)
                            logger.warning(
                                "Throttling encountered on %s.%s (attempt %d). Backing off %.2fs.",
                                self._service_name, name, attempt + 1, backoff
                            )
                            time.sleep(backoff)
                            continue
                        raise APIThrottledError(
                            f"AWS API call '{name}' throttled and exhausted {max_retries} bounded retries."
                        ) from ce
                    # Non-throttling client errors are passed through to callers (e.g. NoSuchBucket)
                    raise ce

            if last_err:
                raise APIThrottledError(f"Throttled after retries: {last_err}")

        return intercepted_call


class ReadOnlyAWSClientFactory:
    """
    Centralized factory providing strictly read-only, timeout-governed Boto3 clients.
    Excludes mutating operations, unapproved services, and unauthorized regions.
    """

    def __init__(
        self,
        session: Optional[boto3.Session] = None,
        budget: Optional[APICallBudget] = None,
        rate_limiter: Optional[RateLimiter] = None
    ):
        self._session = session
        self.budget = budget or APICallBudget()
        self.rate_limiter = rate_limiter or RateLimiter()

        # Enforce explicit timeouts and standard retry configuration
        self._boto_config = Config(
            connect_timeout=5.0,
            read_timeout=10.0,
            retries={"max_attempts": 3, "mode": "standard"}
        )

    def _get_session(self) -> boto3.Session:
        if self._session is not None:
            return self._session
        from backend.connectors.aws_session import get_boto3_session
        return get_boto3_session()

    def get_client(self, service_name: str, region_name: Optional[str] = None) -> ReadOnlyClientProxy:
        """
        Creates and returns a wrapped ReadOnlyClientProxy for an allowlisted service and region.
        """
        normalized_service = service_name.lower().strip()

        # Enforce service allowlist
        if normalized_service not in ALLOWED_SERVICES:
            raise UnauthorizedServiceError(
                f"AWS service '{service_name}' is not authorized. Allowed services: {sorted(ALLOWED_SERVICES)}"
            )

        # Enforce region allowlist
        target_region = validate_region(region_name, service_name=normalized_service)

        sess = self._get_session()

        # Supply custom timeout configuration if the session/client supports botocore Config
        try:
            raw_client = sess.client(normalized_service, region_name=target_region, config=self._boto_config)
        except (TypeError, ValueError):
            # Fallback for synthetic/mock sessions that don't accept config kwargs
            raw_client = sess.client(normalized_service, region_name=target_region)

        return ReadOnlyClientProxy(
            raw_client=raw_client,
            service_name=normalized_service,
            budget=self.budget,
            rate_limiter=self.rate_limiter
        )
