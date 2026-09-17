"""Tighten mode bits on files that hold secrets."""

from __future__ import annotations

import os
from pathlib import Path


def restrict_private_file(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        return
