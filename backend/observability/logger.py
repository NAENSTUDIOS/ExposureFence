"""
ExposureFence — Structured JSON Logging Service
Outputs machine-readable JSON log events with correlation IDs and security event markers.
"""

from datetime import datetime, timezone
import json
import logging
import sys
from typing import Any, Dict, Optional


class JSONFormatter(logging.Formatter):
    """Formats log records as structured single-line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno
        }
        if hasattr(record, "correlation_id"):
            log_obj["correlation_id"] = record.correlation_id
        if hasattr(record, "security_event_id"):
            log_obj["security_event_id"] = record.security_event_id

        return json.dumps(log_obj)


def get_structured_logger(name: str = "exposurefence") -> logging.Logger:
    """Returns a configured structured JSON logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
