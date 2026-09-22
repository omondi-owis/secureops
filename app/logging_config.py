"""Structured application logging.

Never logs passwords, tokens, API keys or session secrets — callers are
responsible for redacting values before logging.
"""
from __future__ import annotations

import logging
import sys

_CONFIGURED = False


def configure_logging(level: int | str = logging.INFO) -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
            "%Y-%m-%d %H:%M:%S",
        )
    )
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    # Keep noisy third-party libraries quiet.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    if not _CONFIGURED:
        configure_logging()
    return logging.getLogger(name)
