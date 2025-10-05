"""Centralized logging configuration for the backend services."""

import logging
import os
from logging.config import dictConfig
from typing import Any, Dict


def _build_logging_config(level: str) -> Dict[str, Any]:
    """Return a dictConfig-style logging configuration.

    Parameters
    ----------
    level: str
        The log level to apply to the root logger.
    """

    formatter = {
        "format": "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    }

    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {"default": formatter},
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
            }
        },
        "root": {
            "handlers": ["console"],
            "level": level,
        },
    }


def setup_logging() -> None:
    """Configure logging for the application.

    The configuration is applied only once even if the function is invoked
    multiple times.
    """

    if getattr(setup_logging, "_configured", False):  # pragma: no cover - defensive
        return

    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    dictConfig(_build_logging_config(log_level))
    logging.getLogger(__name__).debug("Logging configured with level %s", log_level)
    setattr(setup_logging, "_configured", True)

