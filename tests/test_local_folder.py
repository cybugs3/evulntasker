from pathlib import Path

import pytest

from app.services.file_ingest import local_folder


def test_local_folder_rejects_empty():
    with pytest.raises(ValueError, match="Enter a folder path"):
        local_folder("  ")


def test_local_folder_rejects_windows_path():
    with pytest.raises(ValueError, match="Windows path"):
        local_folder(r"C:\Users\guy\inbox")


def test_local_folder_accepts_existing_dir(tmp_path: Path):
    (tmp_path / "note.txt").write_text("CVE-2024-3094", encoding="utf-8")
    resolved = local_folder(str(tmp_path))
    assert resolved.is_dir()
    assert resolved == tmp_path.resolve()


def test_local_folder_missing_dir(tmp_path: Path):
    missing = tmp_path / "nope"
    with pytest.raises(ValueError, match="Folder not found on this server"):
        local_folder(str(missing))
