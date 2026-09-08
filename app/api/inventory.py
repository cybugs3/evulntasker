"""Org inventory API — local catalog used for CVE relevance matching."""

from __future__ import annotations

from collections import Counter
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.api.settings.common import save_env
from app.config import get_settings
from app.db.session import get_db
from app.models.asset import Asset, AssetMatch
from app.models.vulnerability import Vulnerability
from app.services.inventory_sources import (
    classify_asset_origin,
    is_library,
    list_source_specs,
)
from app.services.inventory_sync import (
    catalog_rows,
    delete_asset,
    import_csv_text,
    inventory_status,
    sample_csv_text,
    save_manual_asset,
    sync_all,
)

router = APIRouter()

RELEVANT_METHODS = frozenset({"cmdb", "sonatype", "local", "csv", "itnm"})
RELEVANT_MIN_CONFIDENCE = 0.8


class InventoryScheduleIn(BaseModel):
    enabled: bool = False
    sync_seconds: int = Field(default=1800, ge=60, le=604800)


class AssetWrite(BaseModel):
    vendor: str = Field(min_length=1, max_length=128)
    product: str = Field(min_length=1, max_length=128)
    product_type: str = Field(default="", max_length=64)
    version: str = Field(default="", max_length=64)
    owner_name: str = Field(default="", max_length=128)
    owner_email: str = Field(default="", max_length=256)
    team: str = Field(default="", max_length=128)
    name: str = Field(default="", max_length=256)


def _inventory_match_kpis(db: Session) -> dict[str, Any]:
    cross_matches = db.query(func.count(AssetMatch.id)).scalar() or 0
    relevant_filter = (
        AssetMatch.method.in_(RELEVANT_METHODS),
        AssetMatch.confidence >= RELEVANT_MIN_CONFIDENCE,
    )
    relevant_hits = db.query(func.count(AssetMatch.id)).filter(*relevant_filter).scalar() or 0
    relevant = (
        db.query(func.count(func.distinct(AssetMatch.vulnerability_id))).filter(*relevant_filter).scalar()
        or 0
    )
    ai_only = db.query(func.count(AssetMatch.id)).filter(AssetMatch.method == "ai").scalar() or 0
    enriched_like = (
        db.query(func.count(Vulnerability.id))
        .filter(
            Vulnerability.pipeline_status.in_(
                [
                    "enriched",
                    "matched",
                    "actioned",
                    "completed",
                    "ai_fallback",
                    "ENRICHED",
                    "MATCHED",
                    "ACTIONED",
                    "AI_FALLBACK",
                ]
            )
        )
        .scalar()
        or 0
    )
    if enriched_like == 0:
        enriched_like = db.query(func.count(Vulnerability.id)).scalar() or 0
    relevance_rate = round(100.0 * relevant / enriched_like, 1) if enriched_like else 0.0
    return {
        "cross_matches": int(cross_matches),
        "relevant": int(relevant),
        "relevant_hits": int(relevant_hits),
        "ai_inferred": int(ai_only),
        "relevance_rate": relevance_rate,
        "enriched_like": int(enriched_like),
    }


@router.get("/inventory")
def org_inventory(db: Session = Depends(get_db), include_details: bool = True) -> dict[str, Any]:
    cfg = get_settings()
    specs = list_source_specs(cfg)

    if not include_details:
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
        match_kpis = _inventory_match_kpis(db)
        enabled_sources = sum(1 for spec in specs if spec["enabled"])
        return {
            "kpis": {
                "sources": len(specs),
                "sources_online": enabled_sources,
                "systems": systems,
                "libraries": libraries,
                "assets_total": len(asset_cols),
                "teams_count": len(teams),
                "cross_matches": match_kpis["cross_matches"],
                "relevant": match_kpis["relevant"],
                "relevant_hits": match_kpis["relevant_hits"],
                "ai_inferred": match_kpis["ai_inferred"],
                "relevance_rate": match_kpis["relevance_rate"],
            },
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
    systems = 0
    libraries = 0
    teams: Counter[str] = Counter()
    system_types: Counter[str] = Counter()

    for asset in assets:
        origin = classify_asset_origin(asset)
        by_origin[origin] += 1
        st = (asset.system_type or "unknown").strip().lower() or "unknown"
        system_types[st] += 1
        if is_library(st):
            libraries += 1
        else:
            systems += 1
        if asset.team:
            teams[asset.team] += 1

    matches = (
        db.query(AssetMatch)
        .options(joinedload(AssetMatch.vulnerability), joinedload(AssetMatch.asset))
        .all()
    )
    cross_matches = len(matches)
    relevant_matches = [
        m
        for m in matches
        if (m.method or "") in RELEVANT_METHODS and float(m.confidence or 0) >= RELEVANT_MIN_CONFIDENCE
    ]
    relevant_vuln_ids = {m.vulnerability_id for m in relevant_matches}
    ai_only = sum(1 for m in matches if (m.method or "") == "ai")

    method_counts: Counter[str] = Counter((m.method or "unknown") for m in matches)

    enriched_like = (
        db.query(func.count(Vulnerability.id))
        .filter(
            Vulnerability.pipeline_status.in_(
                [
                    "enriched",
                    "matched",
                    "actioned",
                    "completed",
                    "ai_fallback",
                    "ENRICHED",
                    "MATCHED",
                    "ACTIONED",
                    "AI_FALLBACK",
                ]
            )
        )
        .scalar()
        or 0
    )
    if enriched_like == 0:
        enriched_like = db.query(func.count(Vulnerability.id)).scalar() or 0

    relevance_rate = (
        round(100.0 * len(relevant_vuln_ids) / enriched_like, 1) if enriched_like else 0.0
    )

    sources_out = []
    for spec in specs:
        origin = spec["asset_origin"]
        method = spec["match_method"]
        asset_count = by_origin.get(origin, 0)
        match_count = method_counts.get(method, 0)
        src_state = (setup.get("sources") or {}).get(origin) or {}
        sources_out.append(
            {
                **spec,
                "assets": asset_count,
                "matches": match_count,
                "status": "online" if spec["enabled"] else "offline",
                "health": _source_health(spec["enabled"], asset_count, match_count),
                "last_sync_at": src_state.get("last_sync_at"),
                "last_error": src_state.get("last_error"),
                "configured": src_state.get("configured"),
            }
        )

    top_teams = [{"team": name, "assets": count} for name, count in teams.most_common(8)]
    type_breakdown = [
        {"type": name, "count": count, "kind": "library" if is_library(name) else "system"}
        for name, count in system_types.most_common(12)
    ]

    recent_relevant = []
    for match in sorted(relevant_matches, key=lambda m: m.created_at or m.id, reverse=True)[:25]:
        vuln = match.vulnerability
        asset = match.asset
        if vuln is None or asset is None:
            continue
        recent_relevant.append(
            {
                "cve_id": vuln.cve_id,
                "vendor": vuln.vendor,
                "product": vuln.product,
                "asset": asset.name,
                "system_type": asset.system_type,
                "team": asset.team,
                "owner": asset.owner_name,
                "method": match.method,
                "confidence": round(float(match.confidence or 0), 2),
                "href": f"/vulnerabilities/{vuln.cve_id}",
                "matching_href": "/matching",
            }
        )

    enabled_sources = sum(1 for s in sources_out if s["enabled"])
    return {
        "kpis": {
            "sources": len(sources_out),
            "sources_online": enabled_sources,
            "systems": systems,
            "libraries": libraries,
            "assets_total": len(assets),
            "teams_count": len(teams),
            "cross_matches": cross_matches,
            "relevant": len(relevant_vuln_ids),
            "relevant_hits": len(relevant_matches),
            "ai_inferred": ai_only,
            "relevance_rate": relevance_rate,
        },
        "setup": setup,
        "catalog": catalog_rows(db),
        "sources": sources_out,
        "coverage": {
            "cves_considered": enriched_like,
            "cves_relevant": len(relevant_vuln_ids),
            "relevance_rate": relevance_rate,
            "by_method": dict(method_counts),
        },
        "teams": top_teams,
        "types": type_breakdown,
        "relevant_rows": recent_relevant,
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
