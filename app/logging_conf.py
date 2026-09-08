"""
Production logging for a Linux service.

Logs go to both stderr (journald/systemd captures this) and a rotating
file under VULNINTEL_LOG_DIR. Structured extra fields are attached so
pipeline steps can be grepped by cve_id / run_id.
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.config import get_settings

LOG_FORMAT = (
    "%(asctime)s | %(levelname)-8s | %(name)s | %(process)d | %(message)s"
)


def configure_logging() -> None:
    settings = get_settings()
    log_dir: Path = settings.log_dir
    log_dir.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(settings.log_level.upper())

    # Avoid duplicate handlers on uvicorn reload.
    if root.handlers:
        return

    formatter = logging.Formatter(LOG_FORMAT)

    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(formatter)
    root.addHandler(stream)

    file_handler = RotatingFileHandler(
        log_dir / "evulntasker.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=10,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    # Quiet noisy third-party loggers in production.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("apscheduler").setLevel(logging.INFO)
    logging.getLogger("exchangelib").setLevel(logging.WARNING)
