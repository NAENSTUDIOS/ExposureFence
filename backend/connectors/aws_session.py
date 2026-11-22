"""
ExposureFence AWS Session Manager & Secure Mode Configuration
Provides read-only Boto3 session access using the standard AWS credential chain,
named profiles, IAM Identity Center (SSO), and temporary assumed-role credentials.
Enforces explicit data mode separation ('mock' vs 'aws') and rejects silent fallbacks.
"""

import os
from typing import Optional

import boto3
from botocore.exceptions import BotoCoreError, ProfileNotFound

from backend.connectors.exceptions import (
    AWSConfigurationError,
    CredentialsUnavailableError
)


def get_data_mode() -> str:
    """
    Returns the configured data mode: 'mock' (default) or 'aws'.
    AWS mode requires explicit configuration via EXPOSUREFENCE_DATA_MODE=aws.
    Unknown or invalid modes strictly fall back to 'mock'.
    """
    mode = os.getenv("EXPOSUREFENCE_DATA_MODE", "mock").strip().lower()
    if mode == "aws":
        return "aws"
    return "mock"


def is_aws_mode_enabled() -> bool:
    """Returns True ONLY if AWS mode is explicitly enabled."""
    return get_data_mode() == "aws"


def get_boto3_session(
    region_name: Optional[str] = None,
    profile_name: Optional[str] = None
) -> boto3.Session:
    """
    Creates a Boto3 Session using standard environment/profile credential resolution.
    Supports:
      - Default AWS credential provider chain
      - Named AWS profiles (via profile_name or AWS_PROFILE)
      - IAM Identity Center (SSO) and temporary assumed-role credentials
      - Explicit region resolution (region_name, AWS_REGION, AWS_DEFAULT_REGION)

    In AWS mode (EXPOSUREFENCE_DATA_MODE=aws):
      - Verifies that genuine credentials or profiles exist.
      - Fails explicitly with CredentialsUnavailableError if credentials are missing.
      - NEVER silently falls back to mock data while reporting live mode.

    In Mock mode (EXPOSUREFENCE_DATA_MODE=mock):
      - Returns a local session without validating cloud credentials.
    """
    target_region = region_name or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    target_profile = profile_name or os.getenv("AWS_PROFILE")

    session_kwargs = {"region_name": target_region}
    if target_profile:
        session_kwargs["profile_name"] = target_profile

    try:
        session = boto3.Session(**session_kwargs)
    except ProfileNotFound as pnf:
        if is_aws_mode_enabled():
            raise CredentialsUnavailableError(f"AWS profile '{target_profile}' not found: {pnf}") from pnf
        # If in mock mode with a bad profile name, construct clean default session
        session = boto3.Session(region_name=target_region)
    except BotoCoreError as bce:
        if is_aws_mode_enabled():
            raise AWSConfigurationError(f"Failed to initialize Boto3 session: {bce}") from bce
        session = boto3.Session(region_name=target_region)

    # In AWS mode, verify genuine credentials exist
    if is_aws_mode_enabled():
        try:
            creds = session.get_credentials()
            if creds is None:
                raise CredentialsUnavailableError(
                    "AWS mode is active (EXPOSUREFENCE_DATA_MODE=aws), but valid AWS credentials "
                    "were not resolved from environment variables, ~/.aws/credentials, or provider chain."
                )
        except BotoCoreError as e:
            raise CredentialsUnavailableError(f"Error resolving AWS credentials: {e}") from e

    return session
