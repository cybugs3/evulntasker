"""Registry of internal inventory sources used for CVE ↔ org relevance matching.

CSV, CMDB, Sonatype, and ITNM/discovery all populate the local `assets` table.
Matching reads that table only.
"""

from __future__ import annotations

from typing import Any, Callable

from app.config import Settings, get_settings

LIBRARY_TYPES = frozenset({"library", "component", "package", "dependency", "container-image"})


def _cmdb_enabled(cfg: Settings) -> bool:
    return bool(cfg.cmdb_enabled and cfg.cmdb_connection.base_url)


def _sonatype_enabled(cfg: Settings) -> bool:
    return bool(cfg.sonatype_enabled and cfg.sonatype_connection.base_url)


def _itnm_enabled(cfg: Settings) -> bool:
    return bool(cfg.itnm_enabled and cfg.itnm_connection.base_url)


def _csv_enabled(_cfg: Settings) -> bool:
    return True


def _local_enabled(_cfg: Settings) -> bool:
    return True


INTERNAL_SOURCE_SPECS: list[dict[str, Any]] = [
    {
        "id": "csv",
        "name": "CSV catalog",
        "label": "File import",
        "role": "mixed",
        "description": "Vendor, product, product type, and version loaded from a prepared CSV after install.",
        "asset_origin": "csv",
        "match_method": "csv",
        "settings_href": "/inventory",
        "is_enabled": _csv_enabled,
    },
    {
        "id": "cmdb",
        "name": "CMDB",
        "label": "Configuration management",
        "role": "systems",
        "description": "Hosts, applications, and services synced into the local catalog on a schedule.",
        "asset_origin": "cmdb",
        "match_method": "cmdb",
        "settings_href": "/settings#assets",
        "is_enabled": _cmdb_enabled,
    },
    {
        "id": "sonatype",
        "name": "Sonatype",
        "label": "Software composition",
        "role": "libraries",
        "description": "Application components from Nexus Lifecycle / IQ, synced locally.",
        "asset_origin": "sonatype",
        "match_method": "sonatype",
        "settings_href": "/settings#assets",
        "is_enabled": _sonatype_enabled,
    },
    {
        "id": "itnm",
        "name": "ITNM / Discovery",
        "label": "Network inventory",
        "role": "systems",
        "description": "IBM Tivoli Network Manager (or similar discovery) devices synced into the local catalog.",
        "asset_origin": "itnm",
        "match_method": "itnm",
        "settings_href": "/settings#assets",
        "is_enabled": _itnm_enabled,
    },
    {
        "id": "local",
        "name": "Local inventory",
        "label": "On-box catalog",
        "role": "mixed",
        "description": "Rows stored only in EVulnTasker (manual or legacy seed).",
        "asset_origin": "local",
        "match_method": "local",
        "settings_href": "/inventory",
        "is_enabled": _local_enabled,
    },
]


def list_source_specs(cfg: Settings | None = None) -> list[dict[str, Any]]:
    cfg = cfg or get_settings()
    out: list[dict[str, Any]] = []
    for spec in INTERNAL_SOURCE_SPECS:
        enabled_fn: Callable[[Settings], bool] = spec["is_enabled"]
        row = {k: v for k, v in spec.items() if k != "is_enabled"}
        row["enabled"] = bool(enabled_fn(cfg))
        out.append(row)
    return out


def classify_asset_origin(asset: Any) -> str:
    source = (getattr(asset, "source", None) or "").strip().lower()
    if source:
        return source
    if getattr(asset, "cmdb_id", None):
        return "cmdb"
    if getattr(asset, "sonatype_id", None):
        return "sonatype"
    return "local"


def is_library(system_type: str | None) -> bool:
    return (system_type or "").strip().lower() in LIBRARY_TYPES
