"""Org inventory API — local catalog used for CVE relevance matching."""

from __future__ import annotations

from collections import Counter
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.settings.common import save_env
from app.config import get_settings
from app.db.session import get_db
from app.models.asset import Asset
from app.services.inventory_sources import (
    classify_asset_origin,
    is_library,
    list_source_specs,
)
from app.services.inventory_sync import (
    catalog_rows,
    delete_asset,
    delete_assets,
    import_csv_text,
    inventory_status,
    sample_csv_text,
    export_catalog_csv,
    save_manual_asset,
    sync_all,
)

router = APIRouter()


class InventoryScheduleIn(BaseModel):
    enabled: bool = False
    sync_seconds: int = Field(default=86400, ge=60, le=604800)


class AssetDeleteIn(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=5000)


class AssetWrite(BaseModel):
    vendor: str = Field(min_length=1, max_length=128)
    product: str = Field(min_length=1, max_length=128)
    product_type: str = Field(default="", max_length=64)
    version: str = Field(default="", max_length=64)
    owner_name: str = Field(default="", max_length=128)
    owner_email: str = Field(default="", max_length=256)
    team: str = Field(default="", max_length=128)
    name: str = Field(default="", max_length=256)


def _catalog_kpis(db: Session) -> dict[str, Any]:
    asset_cols = db.query(Asset.system_type, Asset.team).filter(Asset.active.is_(True)).all()
    systems = 0
    libraries = 0
    teams: Counter[str] = Counter()
    for system_type, team in asset_cols:
        st = (system_type or "unknown").strip().lower() or "unknown"
        if is_library(st):
            libraries += 1
        else:
            systems += 1
        if team:
            teams[team] += 1
    return {
        "systems": systems,
        "libraries": libraries,
        "assets_total": len(asset_cols),
        "teams_count": len(teams),
        "teams": teams,
    }


@router.get("/inventory")
def org_inventory(db: Session = Depends(get_db), include_details: bool = True) -> dict[str, Any]:
    cfg = get_settings()
    specs = list_source_specs(cfg)
    counts = _catalog_kpis(db)
    enabled_sources = sum(1 for spec in specs if spec["enabled"])
    kpis = {
        "sources": len(specs),
        "sources_online": enabled_sources,
        "systems": counts["systems"],
        "libraries": counts["libraries"],
        "assets_total": counts["assets_total"],
        "teams_count": counts["teams_count"],
        "cross_matches": 0,
        "relevant": 0,
        "relevant_hits": 0,
        "ai_inferred": 0,
        "relevance_rate": 0.0,
    }
    if not include_details:
        return {
            "kpis": kpis,
            "setup": {},
            "catalog": [],
            "sources": [],
            "coverage": {},
            "teams": [],
            "types": [],
            "relevant_rows": [],
            "links": {"matching": "/matching", "settings_assets": "/settings#assets"},
        }

    assets = db.query(Asset).filter(Asset.active.is_(True)).all()
    setup = inventory_status(db)
    by_origin: Counter[str] = Counter()
    system_types: Counter[str] = Counter()
    for asset in assets:
        by_origin[classify_asset_origin(asset)] += 1
        st = (asset.system_type or "unknown").strip().lower() or "unknown"
        system_types[st] += 1

    sources_out = []
    for spec in specs:
        origin = spec["asset_origin"]
        asset_count = by_origin.get(origin, 0)
        src_state = (setup.get("sources") or {}).get(origin) or {}
        sources_out.append(
            {
                **spec,
                "assets": asset_count,
                "matches": 0,
                "status": "online" if spec["enabled"] else "offline",
                "health": _source_health(spec["enabled"], asset_count, 0),
                "last_sync_at": src_state.get("last_sync_at"),
                "last_error": src_state.get("last_error"),
                "configured": src_state.get("configured"),
            }
        )

    top_teams = [{"team": name, "assets": count} for name, count in counts["teams"].most_common(8)]
    type_breakdown = [
        {"type": name, "count": count, "kind": "library" if is_library(name) else "system"}
        for name, count in system_types.most_common(12)
    ]
    return {
        "kpis": kpis,
        "setup": setup,
        "catalog": catalog_rows(db, limit=100_000),
        "sources": sources_out,
        "coverage": {
            "cves_considered": 0,
            "cves_relevant": 0,
            "relevance_rate": 0.0,
            "by_method": {},
        },
        "teams": top_teams,
        "types": type_breakdown,
        "relevant_rows": [],
        "links": {
            "matching": "/matching",
            "settings_assets": "/settings#assets",
        },
    }


@router.get("/inventory/sample.csv")
@router.get("/inventory/template.csv")
def download_sample_csv() -> PlainTextResponse:
    return PlainTextResponse(
        sample_csv_text(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="internal-systems.csv"'},
    )


@router.get("/inventory/export.csv")
def export_inventory_csv(db: Session = Depends(get_db)) -> PlainTextResponse:
    return PlainTextResponse(
        export_catalog_csv(db),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="systems-database.csv"'},
    )


@router.post("/inventory/assets")
def create_inventory_asset(body: AssetWrite, db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        asset, _created = save_manual_asset(db, body.model_dump())
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True, "id": asset.id, "setup": inventory_status(db)}


@router.put("/inventory/assets/{asset_id}")
def update_inventory_asset(asset_id: int, body: AssetWrite, db: Session = Depends(get_db)) -> dict[str, Any]:
    asset = db.query(Asset).filter(Asset.id == asset_id).one_or_none()
    if asset is None:
        raise HTTPException(404, "System not found")
    try:
        save_manual_asset(db, body.model_dump(), asset=asset)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"ok": True, "id": asset_id, "setup": inventory_status(db)}


@router.post("/inventory/assets/delete")
def remove_inventory_assets(body: AssetDeleteIn, db: Session = Depends(get_db)) -> dict[str, Any]:
    deleted = delete_assets(db, body.ids)
    return {"ok": True, "deleted": deleted, "setup": inventory_status(db)}


@router.delete("/inventory/assets/{asset_id}")
def remove_inventory_asset(asset_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    if not delete_asset(db, asset_id):
        raise HTTPException(404, "System not found")
    return {"ok": True, "setup": inventory_status(db)}


@router.post("/inventory/csv")
async def upload_inventory_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    filename = (file.filename or "assets.csv").lower()
    if not filename.endswith(".csv"):
        raise HTTPException(400, "Upload a .csv file with vendor, product, product_type, version columns.")
    raw = await file.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(400, "CSV must be UTF-8.") from exc
    try:
        result = import_csv_text(db, text)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(400, f"CSV import failed: {exc}") from exc
    return {"ok": True, **result, "setup": inventory_status(db)}


@router.post("/inventory/sync")
def sync_inventory_now(db: Session = Depends(get_db)) -> dict[str, Any]:
    result = sync_all(db)
    if result.get("error") and not result.get("results"):
        raise HTTPException(409, result["error"])
    return {**result, "setup": inventory_status(db)}


@router.post("/inventory/sync/{source}")
def sync_one_source(source: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    if source not in {"csv", "cmdb", "sonatype", "itnm"}:
        raise HTTPException(400, "Unknown inventory source")
    result = sync_all(db, sources=[source])
    if result.get("error") and not result.get("results"):
        raise HTTPException(409, result["error"])
    return {**result, "setup": inventory_status(db)}


@router.put("/inventory/schedule")
def save_inventory_schedule(body: InventoryScheduleIn) -> dict[str, Any]:
    seconds = int(body.sync_seconds)
    save_env(
        {
            "INVENTORY_SYNC_ENABLED": "true" if body.enabled else "false",
            "INVENTORY_SYNC_SECONDS": str(seconds),
        }
    )
    return {"ok": True, "enabled": body.enabled, "sync_seconds": seconds}


def _source_health(enabled: bool, assets: int, matches: int) -> str:
    if not enabled:
        return "disabled"
    if assets == 0 and matches == 0:
        return "empty"
    if matches == 0:
        return "idle"
    return "active"
