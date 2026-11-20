"""
ExposureFence Evidence Engine Exceptions
Defines typed exception hierarchy for schema, canonicalization, integrity, freshness,
and relationship operations.
"""


class EvidenceError(Exception):
    """Base exception for all Evidence Engine errors."""
    pass


class EvidenceSchemaValidationError(EvidenceError):
    """Raised when an evidence record fails data contract or schema validation."""
    pass


class CanonicalizationError(EvidenceError):
    """Raised when JSON Canonicalization (RFC 8785) fails."""
    pass


class EvidenceIntegrityError(EvidenceError):
    """Raised when payload or record cryptographic hash mismatch occurs."""
    pass


class EvidenceTamperingError(EvidenceError):
    """Raised when ledger chain tampering, break in sequence, or unauthorized mutation is detected."""
    pass


class EvidenceFreshnessError(EvidenceError):
    """Raised when evidence fails freshness policy evaluation."""
    pass


class EvidenceNotFoundError(EvidenceError):
    """Raised when a requested evidence record does not exist in the ledger."""
    pass


class EvidenceRelationshipError(EvidenceError):
    """Raised when binding an evidence record to a finding or proposal fails."""
    pass
