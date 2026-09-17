"""Ingest CVE records from a text blob (plain text, HTML, CSV, JSON) into the queue."""

from __future__ import annotations

import os
import re
from pathlib import Path

from sqlalchemy.orm import Session

from app.models.source import InputSource
from app.services.ingestion import ingest_payload
from app.services.intel_parse import parse_intel
from app.utils.cve import extract_cves

TEXT_SUFFIXES = {
    ".txt",
    ".csv",
    ".json",
    ".md",
    ".log",
    ".xml",
    ".lst",
    ".html",
    ".htm",
    ".xhtml",
    ".nfo",
    ".yaml",
    ".yml",
    ".eml",
    ".rtf",
}
MAX_FILE_BYTES = 20 * 1024 * 1024
_WINDOWS_PATH = re.compile(r"^[A-Za-z]:[\\/]|^\\\\")


def local_folder(raw: str | None) -> Path:
    """Resolve a local ingest folder on this host. Raises ValueError if unusable."""
    text = (raw or "").strip().strip('"').strip("'")
    if not text:
        raise ValueError("Enter a folder path on this EVulnTasker server.")
    folder = Path(text).expanduser()
    if _WINDOWS_PATH.match(text) or "\\" in text:
        raise ValueError(
            "That looks like a Windows path. Use a Linux folder on the EVulnTasker server, "
            "for example /var/evulntasker/inbox."
        )
    try:
        folder = folder.resolve(strict=False)
    except OSError:
        pass
    if not folder.exists():
        raise ValueError(
            f"Folder not found on this server: {folder}. "
            "The path must exist on the EVulnTasker host, not on your workstation."
        )
    if not folder.is_dir():
        raise ValueError(f"Not a folder: {folder}")
    if not os.access(folder, os.R_OK | os.X_OK):
        raise ValueError(f"Permission denied: {folder}")
    return folder


def ingest_text(
    db: Session,
    source: InputSource,
    text: str,
    filename: str = "",
    extra: dict | None = None,
) -> int:
    records = parse_intel(text, filename=filename)
    cves = list(dict.fromkeys([rec.cve_id for rec in records] + extract_cves(text)))
    if not cves:
        return 0
    by_id = {rec.cve_id: rec for rec in records}
    payload = {
        "filename": filename,
        "cves": cves,
        "records": [
            {
                "cve_id": cve,
                "vendor": getattr(by_id.get(cve), "vendor", None),
                "product": getattr(by_id.get(cve), "product", None),
                "version": getattr(by_id.get(cve), "version", None),
                "summary": getattr(by_id.get(cve), "summary", None),
            }
            for cve in cves
        ],
    }
    for key, value in (extra or {}).items():
        if value not in (None, ""):
            payload[key] = value
    event = ingest_payload(db, source, payload=payload, raw_text=text)
    return 1 if event else 0


def read_as_text(path: Path) -> str | None:
    """Read a dropped file as text. HTML and other markup are included."""
    try:
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def is_readable(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in TEXT_SUFFIXES or suffix == "":
        return True
    # Unknown extension: still try if it looks like text/HTML.
    return suffix not in {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".exe", ".bin"}
