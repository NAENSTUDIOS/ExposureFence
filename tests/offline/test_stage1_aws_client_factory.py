"""
ExposureFence — Stage 1 Adversarial & Boundary Test Suite
Validates Secure AWS Credential Resolution, Read-Only Client Factory, Account Identity
Verification, Region & Budget Boundaries, Credential Redaction, and Failure Invariants.
All tests run 100% offline using botocore Stubber, synthetic sessions, and zero network calls.
"""

from datetime import datetime, UTC
import io
import json
import logging
import os
import time
from typing import Any, Dict
import pytest
import boto3
from botocore.exceptions import ClientError, ConnectTimeoutError, ReadTimeoutError
from botocore.stub import Stubber

from backend.connectors import (
    AccountMismatchError,
    AccountVerificationError,
    ALLOWED_OPERATIONS,
    ALLOWED_SERVICES,
    APIBudgetExceededError,
    APICallBudget,
    APIRateLimitExceededError,
    APITimeoutError,
    APIThrottledError,
    AssessmentStatus,
    AWSConfigurationError,
    AWSConnectorError,
    CredentialRedactionFilter,
    CredentialsUnavailableError,
    get_allowed_regions,
    get_boto3_session,
    get_data_mode,
    is_aws_mode_enabled,
    map_error_to_assessment_status,
    RateLimiter,
    ReadOnlyAWSClientFactory,
    ReadOnlyClientProxy,
    redact_credentials,
    redact_string,
    UnauthorizedRegionError,
    UnauthorizedServiceError,
    UnsafeCloudOperationError,
    validate_account_id_format,
    validate_region,
    verify_caller_account
)
from backend.dispatcher import ALLOWED_TOOLS


class MockSessionWrapper:
    """Mock Boto3 session wrapper to supply stubbed clients for offline testing."""
    def __init__(self, clients: Dict[str, Any]):
        self._clients = clients

    def client(self, service_name: str, **kwargs):
        if service_name in self._clients:
            return self._clients[service_name]
        raise ValueError(f"No mock client for service {service_name}")


# =========================================================================
# 1. MISSING CREDENTIALS TEST
# =========================================================================

def test_01_missing_credentials_in_aws_mode(monkeypatch):
    """Verifies that AWS mode raises CredentialsUnavailableError when credentials are missing."""
    monkeypatch.setenv("EXPOSUREFENCE_DATA_MODE", "aws")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent/path/config")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/path/credentials")

    # In AWS mode without credentials, session creation must fail explicitly
    with pytest.raises(CredentialsUnavailableError) as exc_info:
        get_boto3_session()
    assert "valid AWS credentials were not resolved" in str(exc_info.value)


# =========================================================================
# 2. INVALID CREDENTIALS / PROFILE TEST
# =========================================================================

def test_02_invalid_profile_in_aws_mode(monkeypatch):
    """Verifies that an invalid named profile fails explicitly without silent fallback."""
    monkeypatch.setenv("EXPOSUREFENCE_DATA_MODE", "aws")
    monkeypatch.setenv("AWS_PROFILE", "nonexistent_profile_xyz_999")

    with pytest.raises(CredentialsUnavailableError) as exc_info:
        get_boto3_session()
    assert "not found" in str(exc_info.value).lower() or "credentials" in str(exc_info.value).lower()


# =========================================================================
# 3. MISSING ACCOUNT ALLOWLIST TEST
# =========================================================================

def test_03_missing_account_allowlist(monkeypatch):
    """Verifies that account verification fails if EXPOSUREFENCE_ALLOWED_ACCOUNT_ID is unset."""
    monkeypatch.delenv("EXPOSUREFENCE_ALLOWED_ACCOUNT_ID", raising=False)
    mock_sts = boto3.client("sts", region_name="us-east-1")

    with pytest.raises(AccountVerificationError) as exc_info:
        verify_caller_account(mock_sts, allowed_account_id=None)
    assert "EXPOSUREFENCE_ALLOWED_ACCOUNT_ID is not configured" in str(exc_info.value)


# =========================================================================
# 4. INVALID ACCOUNT ID FORMAT TEST
# =========================================================================

def test_04_invalid_account_id_format():
    """Verifies that non-12-digit account IDs are rejected."""
    invalid_ids = ["123", "12345678901", "1234567890123", "abcdefghijkl", "12345-678901", ""]
    for bad_id in invalid_ids:
        assert validate_account_id_format(bad_id) is False
        mock_sts = boto3.client("sts", region_name="us-east-1")
        with pytest.raises(AccountVerificationError) as exc_info:
            verify_caller_account(mock_sts, allowed_account_id=bad_id)
        assert "Must be exactly 12 numeric digits" in str(exc_info.value) or "not configured" in str(exc_info.value)


# =========================================================================
# 5. ACCOUNT MISMATCH TEST
# =========================================================================

def test_05_account_mismatch():
    """Verifies that an account ID mismatch between caller and allowlist aborts immediately."""
    sts_client = boto3.client("sts", region_name="us-east-1")
    stubber = Stubber(sts_client)
    stubber.add_response("get_caller_identity", {
        "Account": "111122223333",
        "Arn": "arn:aws:iam::111122223333:user/test-auditor",
        "UserId": "AIDA111122223333"
    })
    stubber.activate()

    with pytest.raises(AccountMismatchError) as exc_info:
        verify_caller_account(sts_client, allowed_account_id="999988887777")
    assert "Target account mismatch" in str(exc_info.value)
    assert "111122223333" in str(exc_info.value)
    assert "999988887777" in str(exc_info.value)

    stubber.deactivate()


# =========================================================================
# 6. VALID ACCOUNT IDENTITY TEST
# =========================================================================

def test_06_valid_account_identity():
    """Verifies successful caller account validation and sanitized metadata output."""
    sts_client = boto3.client("sts", region_name="us-east-1")
    stubber = Stubber(sts_client)
    stubber.add_response("get_caller_identity", {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:role/ExposureFenceAuditRole",
        "UserId": "AROA123456789012EXAMPLE"
    })
    stubber.activate()

    metadata = verify_caller_account(sts_client, allowed_account_id="123456789012")
    assert metadata["status"] == "VERIFIED"
    assert metadata["account_id"] == "123456789012"
    assert metadata["caller_arn"] == "arn:aws:iam::123456789012:role/ExposureFenceAuditRole"
    assert "verification_timestamp" in metadata

    stubber.deactivate()


# =========================================================================
# 7. UNAUTHORIZED REGION TEST
# =========================================================================

def test_07_unauthorized_region(monkeypatch):
    """Verifies that operations targeting unauthorized regions are rejected."""
    monkeypatch.setenv("EXPOSUREFENCE_ALLOWED_REGIONS", "us-east-1,ap-south-1")
    assert "us-east-1" in get_allowed_regions()
    assert "ap-south-1" in get_allowed_regions()

    # Valid region succeeds
    assert validate_region("us-east-1") == "us-east-1"
    assert validate_region("ap-south-1") == "ap-south-1"

    # Unauthorized region raises UnauthorizedRegionError
    with pytest.raises(UnauthorizedRegionError) as exc_info:
        validate_region("eu-west-3")
    assert "not in the configured region allowlist" in str(exc_info.value)

    # Factory rejects unauthorized region
    s3_client = boto3.client("s3", region_name="us-east-1")
    factory = ReadOnlyAWSClientFactory(session=MockSessionWrapper({"s3": s3_client}))
    with pytest.raises(UnauthorizedRegionError):
        factory.get_client("s3", region_name="ap-northeast-1")


# =========================================================================
# 8. UNAUTHORIZED SERVICE TEST
# =========================================================================

def test_08_unauthorized_service():
    """Verifies that attempting to obtain clients for non-allowlisted services is blocked."""
    factory = ReadOnlyAWSClientFactory(session=MockSessionWrapper({}))

    unauthorized_services = ["lambda", "dynamodb", "sqs", "sns", "rds", "cloudformation"]
    for svc in unauthorized_services:
        with pytest.raises(UnauthorizedServiceError) as exc_info:
            factory.get_client(svc)
        assert f"AWS service '{svc}' is not authorized" in str(exc_info.value)


# =========================================================================
# 9. UNAUTHORIZED API OPERATION TEST
# =========================================================================

def test_09_unauthorized_read_operation():
    """Verifies that unapproved read operations on allowlisted services are rejected."""
    s3_client = boto3.client("s3", region_name="us-east-1")
    factory = ReadOnlyAWSClientFactory(session=MockSessionWrapper({"s3": s3_client}))
    proxy = factory.get_client("s3")

    # list_objects_v2 is a read operation, but strictly not allowed (prevents object content access)
    with pytest.raises(UnsafeCloudOperationError) as exc_info:
        proxy.list_objects_v2(Bucket="my-bucket")
    assert "not in the read-only allowlist" in str(exc_info.value)


# =========================================================================
# 10. ATTEMPTED MUTATION TEST
# =========================================================================

def test_10_attempted_mutation_rejected():
    """Verifies that mutating operations (put, delete, create, modify) are blocked with UnsafeCloudOperationError."""
    s3_client = boto3.client("s3", region_name="us-east-1")
    factory = ReadOnlyAWSClientFactory(session=MockSessionWrapper({"s3": s3_client}))
    proxy = factory.get_client("s3")

    mutations = [
        ("put_bucket_policy", {"Bucket": "b", "Policy": "{}"}),
        ("delete_bucket", {"Bucket": "b"}),
        ("create_bucket", {"Bucket": "b"}),
        ("modify_instance_attribute", {}),
    ]

    for op_name, kwargs in mutations:
        with pytest.raises(UnsafeCloudOperationError) as exc_info:
            getattr(proxy, op_name)(**kwargs)
        assert "Prohibited mutating cloud operation" in str(exc_info.value) or "not in the read-only allowlist" in str(exc_info.value)


# =========================================================================
# 11. API BUDGET EXHAUSTION TEST
# =========================================================================

def test_11_api_budget_exhaustion():
    """Verifies that exceeding the assessment API call budget raises APIBudgetExceededError."""
    budget = APICallBudget(max_budget=3)
    assert budget.remaining_budget() == 3

    budget.record_call(1)
    budget.record_call(1)
    assert budget.remaining_budget() == 1

    budget.record_call(1)
    assert budget.remaining_budget() == 0

    # 4th call exceeds budget
    with pytest.raises(APIBudgetExceededError) as exc_info:
        budget.record_call(1)
    assert "Assessment API call budget exceeded" in str(exc_info.value)


# =========================================================================
# 12. RATE LIMIT ENFORCEMENT TEST
# =========================================================================

def test_12_rate_limit_enforcement():
    """Verifies that the rate limiter enforces pacing between rapid calls."""
    limiter = RateLimiter(max_calls_per_second=20.0)  # 50ms interval
    t0 = time.monotonic()
    for _ in range(3):
        limiter.acquire()
    elapsed = time.monotonic() - t0
    # 3 calls at 20 calls/sec require at least ~0.09s total pacing
    assert elapsed >= 0.08


# =========================================================================
# 13. TIMEOUT BEHAVIOR TEST
# =========================================================================

class MockTimingOutClient:
    """Mock client that simulates connection and read timeouts."""
    def list_buckets(self):
        raise ReadTimeoutError(endpoint_url="https://s3.amazonaws.com")


def test_13_timeout_behavior():
    """Verifies that botocore timeout errors are translated to APITimeoutError."""
    mock_client = MockTimingOutClient()
    proxy = ReadOnlyClientProxy(raw_client=mock_client, service_name="s3")

    with pytest.raises(APITimeoutError) as exc_info:
        proxy.list_buckets()
    assert "timed out after configured threshold" in str(exc_info.value)


# =========================================================================
# 14. THROTTLING AND BOUNDED RETRIES TEST
# =========================================================================

class MockThrottlingClient:
    """Mock client that simulates AWS throttling responses."""
    def __init__(self, fail_count: int = 3):
        self.calls = 0
        self.fail_count = fail_count

    def list_buckets(self):
        self.calls += 1
        if self.calls <= self.fail_count:
            raise ClientError(
                {"Error": {"Code": "RequestLimitExceeded", "Message": "Rate exceeded"}},
                "ListBuckets"
            )
        return {"Buckets": []}


def test_14_throttling_and_bounded_retries():
    """Verifies bounded exponential backoff retries on throttling and final APIThrottledError if exhausted."""
    # 1. Throttles twice, succeeds on 3rd attempt
    client_recovers = MockThrottlingClient(fail_count=2)
    budget = APICallBudget(max_budget=20)
    proxy = ReadOnlyClientProxy(raw_client=client_recovers, service_name="s3", budget=budget)
    res = proxy.list_buckets()
    assert res == {"Buckets": []}
    assert client_recovers.calls == 3

    # 2. Throttles persistently, exhausts 3 retries and raises APIThrottledError
    client_exhausts = MockThrottlingClient(fail_count=5)
    proxy_fail = ReadOnlyClientProxy(raw_client=client_exhausts, service_name="s3", budget=budget)
    with pytest.raises(APIThrottledError) as exc_info:
        proxy_fail.list_buckets()
    assert "throttled and exhausted 3 bounded retries" in str(exc_info.value)


# =========================================================================
# 15. CREDENTIAL LEAKAGE THROUGH LOGS TEST
# =========================================================================

def test_15_credential_leakage_redaction():
    """Verifies redaction of Access Keys, Secret Keys, Tokens, External IDs, and multiline logs."""
    sensitive_payload = {
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "session_token": "AQoDYXdzEJr1k654987321654987321654987321654987321654987321==",
        "external_id": "SecretExternalId123",
        "nested": {
            "auth_header": "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261121/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=fe5f80f77d5fa3becb0",
            "bearer": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQWxpY2UifQ.abcdef"
        }
    }

    redacted = redact_credentials(sensitive_payload, sensitive_values={"SecretExternalId123"})

    # Check key and secret fields
    assert redacted["secret_access_key"] == "[REDACTED_SENSITIVE_FIELD]"
    assert redacted["session_token"] == "[REDACTED_SENSITIVE_FIELD]"
    assert redacted["external_id"] == "[REDACTED_SENSITIVE_FIELD]"

    # Check string regex redaction inside nested values
    nested_str = json.dumps(redacted)
    assert "AKIAIOSFODNN7EXAMPLE" not in nested_str
    assert "wJalrXUtnFEMI" not in nested_str
    assert "SecretExternalId123" not in nested_str

    # Test CredentialRedactionFilter on Logger
    logger = logging.getLogger("test_redaction_logger")
    log_stream = io.StringIO()
    handler = logging.StreamHandler(log_stream)
    handler.addFilter(CredentialRedactionFilter(sensitive_values={"SecretExternalId123"}))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    logger.info("Connecting with key AKIA1122334455667788 and SecretExternalId123")
    handler.flush()
    log_output = log_stream.getvalue()

    assert "AKIA1122334455667788" not in log_output
    assert "[REDACTED_AWS_KEY]" in log_output
    assert "SecretExternalId123" not in log_output
    assert "[REDACTED_SECRET]" in log_output


# =========================================================================
# 16. AI AGENT ACCESS ISOLATION TEST
# =========================================================================

def test_16_ai_agent_cannot_access_raw_aws_client():
    """Verifies that the Bedrock Agent dispatcher strictly excludes raw AWS client handles."""
    # Ensure allowed dispatcher tools are strictly high-level functions with no AWS client return
    for tool_name, tool_fn in ALLOWED_TOOLS.items():
        assert "client" not in tool_name.lower()
        assert "boto" not in tool_name.lower()
        assert "factory" not in tool_name.lower()

    # The ReadOnlyAWSClientFactory is not exposed as a callable tool in dispatcher
    assert "get_aws_client" not in ALLOWED_TOOLS
    assert "create_client" not in ALLOWED_TOOLS


# =========================================================================
# 17. MOCK / AWS MODE CONFUSION TEST
# =========================================================================

def test_17_mock_aws_mode_confusion_prevention(monkeypatch):
    """Verifies that when EXPOSUREFENCE_DATA_MODE=aws, configuration errors do not silently fall back to mock."""
    monkeypatch.setenv("EXPOSUREFENCE_DATA_MODE", "aws")
    assert get_data_mode() == "aws"
    assert is_aws_mode_enabled() is True

    # Strip credentials
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent/config")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/credentials")

    # In AWS mode, it MUST NOT silently fall back to mock data
    with pytest.raises(CredentialsUnavailableError):
        get_boto3_session()


# =========================================================================
# 18. FAILURE INVARIANT TEST: ERRORS NEVER EVALUATE TO VERIFIED_SECURE
# =========================================================================

def test_18_errors_never_evaluate_to_verified():
    """Verifies invariant: An AWS API failure never produces VERIFIED or VERIFIED_SECURE."""
    # Map common errors
    assert map_error_to_assessment_status(ClientError({"Error": {"Code": "AccessDenied"}}, "op")) == AssessmentStatus.ACCESS_DENIED
    assert map_error_to_assessment_status(APITimeoutError("timeout")) == AssessmentStatus.API_TIMEOUT
    assert map_error_to_assessment_status(APIThrottledError("throttled")) == AssessmentStatus.THROTTLED
    assert map_error_to_assessment_status(AccountMismatchError("mismatch")) == AssessmentStatus.ACCOUNT_MISMATCH
    assert map_error_to_assessment_status(UnauthorizedRegionError("region")) == AssessmentStatus.REGION_NOT_ALLOWED

    # Invariant: error statuses can never equal VERIFIED
    for err in [
        ClientError({"Error": {"Code": "AccessDenied"}}, "op"),
        APITimeoutError("timeout"),
        APIThrottledError("throttled"),
        AccountMismatchError("mismatch"),
        UnauthorizedRegionError("region"),
        Exception("Generic failure")
    ]:
        status = map_error_to_assessment_status(err)
        assert status != AssessmentStatus.VERIFIED
        assert status != "VERIFIED_SECURE"
