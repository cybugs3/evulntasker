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

# CVE-only wipe (CLI): keep the Internal systems catalog.
KEEP_CVE_WIPE_TABLES = KEEP_CONFIG_TABLES | {
    "assets",
    "inventory_sync_state",
}


def reset_system_data(db: Session) -> dict[str, Any]:
    """Delete Internal systems rows and ingested CVE data. Keep sources and settings."""
    return _wipe_tables(db, KEEP_CONFIG_TABLES)


def wipe_collected_cve_data(db: Session) -> dict[str, Any]:
    """Delete ingested CVEs and pipeline history. Keep Internal systems."""
    return _wipe_tables(db, KEEP_CVE_WIPE_TABLES)


def _wipe_tables(db: Session, keep: set[str]) -> dict[str, Any]:
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

        for source in db.query(InputSource).all():
            if hasattr(source, "event_count"):
                source.event_count = 0
            if hasattr(source, "last_event_at"):
                source.last_event_at = None
            if hasattr(source, "last_error"):
                source.last_error = None
            cfg = dict(source.config or {})
            cfg.pop("seen", None)
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
