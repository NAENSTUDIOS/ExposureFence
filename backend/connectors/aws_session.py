"""
ExposureFence AWS Session Manager & Mode Configuration
Provides read-only Boto3 session access using the standard AWS credential chain.
Enforces explicit data mode separation ('mock' vs 'aws').
"""

import os
from typing import Optional

import boto3


def get_data_mode() -> str:
    """
    Returns the configured data mode: 'mock' (default) or 'aws'.
    AWS mode requires explicit configuration via EXPOSUREFENCE_DATA_MODE=aws.
    """
    mode = os.getenv("EXPOSUREFENCE_DATA_MODE", "mock").strip().lower()
    if mode == "aws":
        return "aws"
    return "mock"


def is_aws_mode_enabled() -> bool:
    """Returns True ONLY if AWS mode is explicitly enabled."""
    return get_data_mode() == "aws"


def get_boto3_session(region_name: Optional[str] = None) -> boto3.Session:
    """
    Creates a Boto3 Session using standard environment/profile credential resolution.
    Does NOT make any network calls during session instantiation.
    """
    target_region = region_name or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    return boto3.Session(region_name=target_region)
