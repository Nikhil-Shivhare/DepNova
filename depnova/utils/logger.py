"""Structured logging setup for DepNova.

Uses structlog for clean, structured log output. Configurable
log level via YAML config or CLI flag.
"""

from __future__ import annotations

import logging
import sys

import structlog


_configured = False


def setup_logging(level: str = "INFO") -> None:
    """Configure structlog with the given log level.

    Call once at startup. Subsequent calls are no-ops.

    Args:
        level: Log level string — DEBUG, INFO, WARNING, ERROR, CRITICAL
    """
    global _configured
    if _configured:
        return

    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Configure stdlib logging (structlog wraps it)
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=numeric_level,
    )

    # Configure structlog processors
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )

    _configured = True


def get_logger(name: str | None = None) -> structlog.BoundLogger:
    """Get a named structlog logger.

    Args:
        name: Logger name (usually __name__ of the calling module)

    Returns:
        A bound structlog logger instance
    """
    return structlog.get_logger(name or "depnova")
