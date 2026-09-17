"""SMB/CIFS client using domain (LDAP/AD) credentials."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

TEXT_SUFFIXES = (".txt", ".csv", ".json", ".md", ".log", ".xml", ".lst")
MAX_BYTES = 5 * 1024 * 1024


@dataclass
class SmbFile:
    name: str
    path: str
    size: int
    content: str


def _username(domain: str, username: str) -> str:
    user = (username or "").strip()
    domain = (domain or "").strip()
    if not domain or "\\" in user or "@" in user:
        return user
    return f"{domain}\\{user}"


def _unc(server: str, share: str, folder: str = "", name: str = "") -> str:
    parts = [server.strip().strip("\\"), share.strip().strip("\\")]
    folder = folder.replace("/", "\\").strip("\\")
    if folder:
        parts.append(folder)
    if name:
        parts.append(name)
    return "\\\\" + "\\".join(parts)


def unc_path(server: str, share: str, folder: str = "") -> str:
    """Full UNC as configured: \\\\server\\share\\folder."""
    return _unc(server, share, folder)


def normalize_locations(cfg: dict[str, Any] | None) -> list[dict[str, str]]:
    """Turn stored config into ``[{name, server, share, path}]`` (legacy single location included)."""
    cfg = dict(cfg or {})
    raw = cfg.get("locations")
    if isinstance(raw, list) and raw:
        items = raw
    elif (cfg.get("server") or "").strip() and (cfg.get("share") or "").strip():
        items = [
            {
                "name": "",
                "server": cfg.get("server") or "",
                "share": cfg.get("share") or "",
                "path": cfg.get("path") or "",
            }
        ]
    else:
        items = []

    out: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        server = str(item.get("server") or "").strip()
        share = str(item.get("share") or "").strip()
        if not server or not share:
            continue
        path = str(item.get("path") or "").strip()
        key = (server.lower(), share.lower(), path.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "name": str(item.get("name") or "").strip(),
                "server": server,
                "share": share,
                "path": path,
            }
        )
    return out


def location_config(base: dict[str, Any] | None, location: dict[str, str]) -> dict[str, Any]:
    merged = dict(base or {})
    merged.update(
        {
            "server": location.get("server") or "",
            "share": location.get("share") or "",
            "path": location.get("path") or "",
        }
    )
    return merged


def register_session(config: dict[str, Any]) -> str:
    try:
        import smbclient
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("smbprotocol is not installed (pip install smbprotocol)") from exc

    server = (config.get("server") or "").strip()
    share = (config.get("share") or "").strip()
    if not server or not share:
        raise ValueError("SMB server and share are required")
    user = _username(config.get("domain") or "", config.get("username") or "")
    password = config.get("password") or ""
    if not user or not password:
        raise ValueError("Domain username and password are required")
    smbclient.register_session(server, username=user, password=password)
    return _unc(server, share, config.get("path") or "")


def test_connection(config: dict[str, Any]) -> dict[str, Any]:
    import smbclient

    root = register_session(config)
    entries = []
    for entry in smbclient.scandir(root):
        entries.append({"name": entry.name, "is_dir": entry.is_dir(), "size": entry.stat().st_size})
        if len(entries) >= 20:
            break
    return {"ok": True, "path": root, "sample": entries}


def test_locations(config: dict[str, Any]) -> dict[str, Any]:
    locations = normalize_locations(config)
    if not locations:
        raise ValueError("Add at least one SMB location (server and share)")
    results: list[dict[str, Any]] = []
    errors: list[str] = []
    for loc in locations:
        label = loc.get("name") or f"{loc['server']}\\{loc['share']}"
        try:
            result = test_connection(location_config(config, loc))
            results.append(
                {
                    "ok": True,
                    "name": loc.get("name") or "",
                    "path": result["path"],
                    "entries": len(result.get("sample") or []),
                    "sample": (result.get("sample") or [])[:5],
                }
            )
        except Exception as exc:
            errors.append(f"{label}: {exc}")
            results.append({"ok": False, "name": loc.get("name") or "", "path": label, "error": str(exc)})
    if errors and not any(row.get("ok") for row in results):
        raise ValueError(errors[0])
    return {"ok": not errors, "locations": results}


def list_text_files(config: dict[str, Any]) -> list[dict[str, Any]]:
    import smbclient

    root = register_session(config)
    files: list[dict[str, Any]] = []
    for entry in smbclient.scandir(root):
        if entry.is_dir():
            continue
        name = entry.name
        if not name.lower().endswith(TEXT_SUFFIXES):
            continue
        stat = entry.stat()
        files.append(
            {
                "name": name,
                "path": _unc(config["server"], config["share"], config.get("path") or "", name),
                "size": stat.st_size,
                "mtime": int(getattr(stat, "st_mtime", 0) or 0),
            }
        )
    return files


def read_text_file(unc_path: str, config: dict[str, Any]) -> str:
    import smbclient

    register_session(config)
    with smbclient.open_file(unc_path, mode="rb") as handle:
        blob = handle.read(MAX_BYTES + 1)
    if len(blob) > MAX_BYTES:
        raise ValueError(f"File exceeds {MAX_BYTES} bytes: {unc_path}")
    return blob.decode("utf-8", errors="replace")
