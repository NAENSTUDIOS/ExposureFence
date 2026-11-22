"""
ExposureFence — AWS Connector Exceptions & Safety Invariants
Defines explicit exceptions for security boundary enforcement, credential validation,
account verification, and read-only client restrictions.
"""


class AWSConnectorError(Exception):
    """Base exception for all ExposureFence AWS connector and client operations."""
    pass


class AWSConfigurationError(AWSConnectorError):
    """Raised when AWS connector configuration (e.g. data mode, region) is invalid."""
    pass


class CredentialsUnavailableError(AWSConfigurationError):
    """Raised when AWS mode is active but genuine AWS credentials cannot be resolved."""
    pass


class AccountVerificationError(AWSConnectorError):
    """Raised when AWS account validation fails or account allowlist is absent/invalid."""
    pass


class AccountMismatchError(AccountVerificationError):
    """Raised when actual caller account does not match the configured allowed account ID."""
    pass


class UnauthorizedRegionError(AWSConnectorError):
    """Raised when an operation targets an AWS region not on the explicit allowlist."""
    pass


class UnauthorizedServiceError(AWSConnectorError):
    """Raised when attempting to obtain an AWS client for a service not on the allowlist."""
    pass


class UnsafeCloudOperationError(AWSConnectorError):
    """Raised when an operation is mutating or not on the read-only operation allowlist."""
    pass


class APIBudgetExceededError(AWSConnectorError):
    """Raised when the assessment-level API call budget is exhausted."""
    pass


class APIRateLimitExceededError(AWSConnectorError):
    """Raised when API call rate limit cannot be satisfied or pacing fails."""
    pass


class APITimeoutError(AWSConnectorError):
    """Raised when an AWS API call exceeds configured connection or read timeouts."""
    pass


class APIThrottledError(AWSConnectorError):
    """Raised when an AWS API call is throttled after exhausting all bounded retries."""
    pass


class CostGateBlockedError(AWSConnectorError):
    """Raised when an AWS API operation is blocked by the Free-Tier-Only Cost Safety Gate."""
    pass

