from pathlib import Path

import pytest

from app.config import get_settings
from app.services.file_ingest import ensure_local_folder_allowed, local_folder


def test_local_folder_rejects_empty():
    with pytest.raises(ValueError, match="Enter a folder path"):
        local_folder("  ")


def test_local_folder_rejects_windows_path():
    with pytest.raises(ValueError, match="Windows path"):
        local_folder(r"C:\Users\guy\inbox")


def test_local_folder_accepts_existing_dir(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("EVULNTASKER_LOCAL_INGEST_ALLOW", str(tmp_path))
    get_settings.cache_clear()
    try:
        (tmp_path / "note.txt").write_text("CVE-2024-3094", encoding="utf-8")
        resolved = local_folder(str(tmp_path))
        assert resolved.is_dir()
        assert resolved == tmp_path.resolve()
    finally:
        monkeypatch.delenv("EVULNTASKER_LOCAL_INGEST_ALLOW", raising=False)
        get_settings.cache_clear()


def test_local_folder_missing_dir(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("EVULNTASKER_LOCAL_INGEST_ALLOW", str(tmp_path))
    get_settings.cache_clear()
    try:
        missing = tmp_path / "nope"
        with pytest.raises(ValueError, match="Folder not found on this server"):
            local_folder(str(missing))
    finally:
        monkeypatch.delenv("EVULNTASKER_LOCAL_INGEST_ALLOW", raising=False)
        get_settings.cache_clear()


def test_local_folder_rejects_etc():
    with pytest.raises(ValueError, match="allowed inbox root"):
        ensure_local_folder_allowed("/etc")


def test_local_folder_rejects_escape_from_tmp():
    with pytest.raises(ValueError, match="allowed inbox root"):
        ensure_local_folder_allowed("/tmp/../etc")
