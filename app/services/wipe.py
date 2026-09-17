"""Reset collected product and CVE tables without touching sources or settings."""

from __future__ import annotations

from typing import Any

from sqlalchemy import inspect, text
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.db.session import Base
from app.models.source import InputSource

KEEP_CONFIG_TABLES = {
    "input_sources",
    "vulnerability_repositories",
    "alembic_version",
}

# CVE-only wipe: keep the Internal systems catalog.
KEEP_CVE_WIPE_TABLES = KEEP_CONFIG_TABLES | {
    "assets",
    "inventory_sync_state",
}


def reset_system_data(db: Session) -> dict[str, Any]:
    """Delete Internal systems rows. Keep CVEs, sources, and settings."""
    return wipe_internal_systems(db)


def wipe_internal_systems(db: Session) -> dict[str, Any]:
    """Delete the Internal systems catalog and its CVE match links."""
    from app.models.asset import Asset, AssetMatch
    from app.models.inventory_sync import InventorySyncState

    bind = db.get_bind()
    if bind.dialect.name == "sqlite":
        db.execute(text("PRAGMA busy_timeout=60000"))

    matches = db.query(AssetMatch).delete(synchronize_session=False)
    sync_rows = db.query(InventorySyncState).delete(synchronize_session=False)
    assets = db.query(Asset).delete(synchronize_session=False)
    db.commit()
    db.expire_all()
    return {
        "ok": True,
        "deleted": {
            "assets": int(assets or 0),
            "asset_matches": int(matches or 0),
            "inventory_sync_state": int(sync_rows or 0),
            "vulnerabilities": 0,
            "ingest_events": 0,
            "pipeline_runs": 0,
        },
        "tables": {
            "assets": int(assets or 0),
            "asset_matches": int(matches or 0),
            "inventory_sync_state": int(sync_rows or 0),
        },
    }


def delete_incoming_cves(db: Session, cve_ids: list[str]) -> dict[str, Any]:
    """Delete selected Incoming CVE rows and their pipeline children. Keep Internal systems."""
    from app.models.asset import AssetMatch
    from app.models.audit import AuditLog
    from app.models.detection import DetectionArtifact
    from app.models.jira import JiraTicket
    from app.models.pipeline import PipelineRun
    from app.models.vulnerability import Vulnerability

    wanted = sorted({(cve or "").strip().upper() for cve in cve_ids if (cve or "").strip()})
    if not wanted:
        raise ValueError("No CVEs selected")
    if len(wanted) > 500:
        raise ValueError("Too many CVEs selected")

    rows = (
        db.query(Vulnerability.id, Vulnerability.cve_id)
        .filter(Vulnerability.cve_id.in_(wanted))
        .all()
    )
    vuln_ids = [row[0] for row in rows]
    found = [row[1] for row in rows]
    if not vuln_ids:
        return {"ok": True, "deleted": 0, "requested": len(wanted)}

    matches = db.query(AssetMatch).filter(AssetMatch.vulnerability_id.in_(vuln_ids)).delete(synchronize_session=False)
    tickets = db.query(JiraTicket).filter(JiraTicket.vulnerability_id.in_(vuln_ids)).delete(synchronize_session=False)
    detections = db.query(DetectionArtifact).filter(DetectionArtifact.vulnerability_id.in_(vuln_ids)).delete(
        synchronize_session=False
    )
    runs = db.query(PipelineRun).filter(PipelineRun.vulnerability_id.in_(vuln_ids)).delete(synchronize_session=False)
    audits = db.query(AuditLog).filter(AuditLog.cve_id.in_(found)).delete(synchronize_session=False)
    deleted = db.query(Vulnerability).filter(Vulnerability.id.in_(vuln_ids)).delete(synchronize_session=False)
    db.commit()
    db.expire_all()
    return {
        "ok": True,
        "deleted": int(deleted or 0),
        "requested": len(wanted),
        "related": {
            "asset_matches": int(matches or 0),
            "tickets": int(tickets or 0),
            "detections": int(detections or 0),
            "pipeline_runs": int(runs or 0),
            "audit_logs": int(audits or 0),
        },
    }


def wipe_collected_cve_data(db: Session) -> dict[str, Any]:
    """Delete ingested CVEs and pipeline history. Keep Internal systems."""
    return _wipe_tables(db, KEEP_CVE_WIPE_TABLES, reset_sources=True)


def _wipe_tables(db: Session, keep: set[str], *, reset_sources: bool = True) -> dict[str, Any]:
    from app import models  # noqa: F401 — register all tables on Base.metadata

    bind = db.get_bind()
    dialect = bind.dialect.name
    inspector = inspect(bind)
    existing = set(inspector.get_table_names())
    targets = [name for name in existing if name not in keep and not name.startswith("sqlite_")]
    keep_sql = ", ".join(f"'{name}'" for name in sorted(keep) if name != "alembic_version")

    if dialect == "sqlite":
        db.commit()
        db.execute(text("PRAGMA foreign_keys = OFF"))
        db.commit()

    deleted: dict[str, int] = {}
    try:
        if dialect == "postgresql" and targets:
            quoted = ", ".join(f'"{name}"' for name in targets)
            db.execute(text(f"TRUNCATE {quoted} RESTART IDENTITY CASCADE"))
            deleted = {name: -1 for name in targets}
        else:
            for table in reversed(list(Base.metadata.sorted_tables)):
                if table.name not in targets:
                    continue
                result = db.execute(text(f'DELETE FROM "{table.name}"'))
                deleted[table.name] = result.rowcount or 0
            leftover = [name for name in targets if name not in deleted]
            for name in leftover:
                result = db.execute(text(f'DELETE FROM "{name}"'))
                deleted[name] = result.rowcount or 0
            if dialect == "sqlite" and keep_sql:
                try:
                    db.execute(text(f"DELETE FROM sqlite_sequence WHERE name NOT IN ({keep_sql})"))
                except Exception:
                    pass

        if reset_sources:
            for source in db.query(InputSource).all():
                if hasattr(source, "event_count"):
                    source.event_count = 0
                if hasattr(source, "last_event_at"):
                    source.last_event_at = None
                if hasattr(source, "last_error"):
                    source.last_error = None
                cfg = dict(source.config or {})
                cfg.pop("seen", None)
                cfg.pop("last_poll_at", None)
                source.config = cfg
                flag_modified(source, "config")

        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        if dialect == "sqlite":
            db.execute(text("PRAGMA foreign_keys = ON"))
            db.commit()

    db.expire_all()
    return {
        "ok": True,
        "deleted": {
            "assets": deleted.get("assets", 0),
            "vulnerabilities": deleted.get("vulnerabilities", 0),
            "ingest_events": deleted.get("ingest_events", 0),
            "pipeline_runs": deleted.get("pipeline_runs", 0),
        },
        "tables": deleted,
    }
