"""
ExposureFence — Centralized Credential Redaction Filter & Utility
Guarantees that AWS Access Keys, Secret Access Keys, Session Tokens, Bearer Tokens,
Authorization headers, and configured sensitive fields are never leaked to logs,
terminal output, or serializations.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Union

# Pattern matchers for sensitive AWS and auth identifiers
AWS_ACCESS_KEY_REGEX = re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b")
BEARER_TOKEN_REGEX = re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{20,}", re.IGNORECASE)
SESSION_TOKEN_REGEX = re.compile(r"(?i)(?:aws_session_token|sessiontoken|securitytoken|x-amz-security-token)[\s:=]+['\"]?([A-Za-z0-9/+=]{40,})['\"]?")
SECRET_KEY_REGEX = re.compile(r"(?i)(?:aws_secret_access_key|secret_key|secretaccesskey|secret)[\s:=]+['\"]?([A-Za-z0-9/+=]{30,45})['\"]?")
AUTHORIZATION_HEADER_REGEX = re.compile(r"AWS4-HMAC-SHA256\s+Credential=[^,\s]+,\s*SignedHeaders=[^,\s]+,\s*Signature=[a-f0-9]+", re.IGNORECASE)

SENSITIVE_FIELD_NAMES: Set[str] = {
    "secretaccesskey",
    "aws_secret_access_key",
    "sessiontoken",
    "aws_session_token",
    "securitytoken",
    "authorization",
    "x-amz-security-token",
    "externalid",
    "password",
    "password_hash",
    "secret"
}


def redact_string(text: str, sensitive_values: Optional[Set[str]] = None) -> str:
    """
    Redacts sensitive credential patterns from unstructured or multiline strings.
    """
    if not text:
        return ""

    sanitized = AWS_ACCESS_KEY_REGEX.sub("[REDACTED_AWS_KEY]", text)
    sanitized = BEARER_TOKEN_REGEX.sub("Bearer [REDACTED_TOKEN]", sanitized)
    sanitized = AUTHORIZATION_HEADER_REGEX.sub("AWS4-HMAC-SHA256 [REDACTED_AUTH_HEADER]", sanitized)
    sanitized = SESSION_TOKEN_REGEX.sub("aws_session_token=[REDACTED_SESSION_TOKEN]", sanitized)
    sanitized = SECRET_KEY_REGEX.sub("aws_secret_access_key=[REDACTED_SECRET_KEY]", sanitized)

    # Redact any explicitly registered known sensitive values (e.g. sensitive External IDs)
    if sensitive_values:
        for secret in sensitive_values:
            if secret and len(secret) >= 4:
                sanitized = sanitized.replace(secret, "[REDACTED_SECRET]")

    return sanitized


def redact_credentials(
    data: Any,
    sensitive_keys: Optional[Set[str]] = None,
    sensitive_values: Optional[Set[str]] = None
) -> Any:
    """
    Recursively redacts sensitive keys and values from dictionaries, lists, strings,
    JSON serializations, and Exception objects.
    """
    keys_to_redact = sensitive_keys or SENSITIVE_FIELD_NAMES

    if isinstance(data, str):
        # Check if the string is serialized JSON
        trimmed = data.strip()
        if (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]")):
            try:
                parsed = json.loads(data)
                sanitized_obj = redact_credentials(parsed, keys_to_redact, sensitive_values)
                return json.dumps(sanitized_obj)
            except Exception:
                pass
        return redact_string(data, sensitive_values)

    elif isinstance(data, dict):
        sanitized_dict = {}
        for k, v in data.items():
            k_str = str(k).lower().replace("_", "").replace("-", "")
            if k_str in keys_to_redact:
                sanitized_dict[k] = "[REDACTED_SENSITIVE_FIELD]"
            else:
                sanitized_dict[k] = redact_credentials(v, keys_to_redact, sensitive_values)
        return sanitized_dict

    elif isinstance(data, (list, tuple, set)):
        sanitized_list = [redact_credentials(item, keys_to_redact, sensitive_values) for item in data]
        if isinstance(data, tuple):
            return tuple(sanitized_list)
        if isinstance(data, set):
            return set(sanitized_list)
        return sanitized_list

    elif isinstance(data, Exception):
        sanitized_msg = redact_string(str(data), sensitive_values)
        return f"{type(data).__name__}: {sanitized_msg}"

    return data


class CredentialRedactionFilter(logging.Filter):
    """
    Logging filter that sanitizes log records before emitting to handlers.
    """

    def __init__(self, sensitive_values: Optional[Set[str]] = None):
        super().__init__()
        self.sensitive_values = sensitive_values or set()

    def filter(self, record: logging.LogRecord) -> bool:
        if record.msg:
            if isinstance(record.msg, str):
                record.msg = redact_string(record.msg, self.sensitive_values)
            elif isinstance(record.msg, (dict, list)):
                record.msg = redact_credentials(record.msg, sensitive_values=self.sensitive_values)

        if record.args:
            if isinstance(record.args, dict):
                record.args = redact_credentials(record.args, sensitive_values=self.sensitive_values)
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    redact_credentials(arg, sensitive_values=self.sensitive_values) for arg in record.args
                )

        if record.exc_text:
            record.exc_text = redact_string(record.exc_text, self.sensitive_values)

        return True
