"""
SQLAlchemy engine and session factory.

SQLite is used for local/dev (check_same_thread=False so FastAPI worker
threads can share the connection). PostgreSQL is used in production via
the same ORM models — only the connection URL changes.
"""

from __future__ import annotations

import logging
from collections.abc import Generator

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

log = logging.getLogger(__name__)

from app.config import get_settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def _build_engine():
    settings = get_settings()
    connect_args = {}
    engine_kwargs: dict = {"pool_pre_ping": True, "future": True}

    if settings.is_sqlite:
        connect_args["check_same_thread"] = False
        # Wait for the writer (scheduler / pipeline) instead of failing fast.
        connect_args["timeout"] = 30
        engine_kwargs["connect_args"] = connect_args
    else:
        engine_kwargs.update(pool_size=10, max_overflow=20)

    engine = create_engine(settings.database_url, **engine_kwargs)

    if settings.is_sqlite:
        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _connection_record):  # type: ignore[no-untyped-def]
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.execute("PRAGMA temp_store=MEMORY")
            cursor.close()

    return engine


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a request-scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _column_ddl(column) -> str:
    type_sql = column.type.compile(dialect=engine.dialect)
    default_sql = ""
    default = column.default.arg if column.default is not None and getattr(column.default, "is_scalar", False) else None
    if default is not None:
        if hasattr(default, "value"):
            default = default.value
        if isinstance(default, str):
            default_sql = f" DEFAULT '{default}'"
        elif isinstance(default, bool):
            default_sql = " DEFAULT 1" if default else " DEFAULT 0"
        else:
            default_sql = f" DEFAULT {default}"
    return f"{column.name} {type_sql}{default_sql}"


def _upgrade_existing_schema() -> None:
    """Add columns/tables that create_all will not add to an existing SQLite file."""
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue
            have = {col["name"] for col in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in have:
                    continue
                conn.execute(text(f"ALTER TABLE {table.name} ADD COLUMN {_column_ddl(column)}"))
                log.info("Added column %s.%s", table.name, column.name)
            inspector.clear_cache()

        inspector.clear_cache()
        if "vulnerabilities" in inspector.get_table_names():
            cols = {col["name"] for col in inspector.get_columns("vulnerabilities")}
            if "status" in cols and "pipeline_status" in cols:
                conn.execute(
                    text(
                        """
                        UPDATE vulnerabilities SET status = CASE pipeline_status
                            WHEN 'extracting' THEN 'EXTRACTED'
                            WHEN 'extracted' THEN 'EXTRACTED'
                            WHEN 'enriching' THEN 'ENRICHED'
                            WHEN 'enriched' THEN 'ENRICHED'
                            WHEN 'waiting_enrichment' THEN 'ENRICHED'
                            WHEN 'matching' THEN 'MATCHED'
                            WHEN 'matched' THEN 'MATCHED'
                            WHEN 'acting' THEN 'ACTIONED'
                            WHEN 'completed' THEN 'ACTIONED'
                            WHEN 'actioned' THEN 'ACTIONED'
                            WHEN 'failed' THEN 'FAILED'
                            ELSE COALESCE(NULLIF(status, ''), 'INGESTED')
                        END
                        WHERE status IS NULL OR status = '' OR status = 'INGESTED'
                        """
                    )
                )
                conn.execute(
                    text(
                        """
                        UPDATE vulnerabilities SET status = 'ENRICHED'
                        WHERE pipeline_status = 'waiting_enrichment'
                          AND status != 'ENRICHED'
                        """
                    )
                )
                conn.execute(
                    text(
                        """
                        UPDATE vulnerabilities SET pipeline_status = CASE status
                            WHEN 'EXTRACTED' THEN 'extracting'
                            WHEN 'ENRICHED' THEN 'enriching'
                            WHEN 'MATCHED' THEN 'matching'
                            WHEN 'ACTIONED' THEN 'completed'
                            WHEN 'AI_FALLBACK' THEN 'enriching'
                            WHEN 'FAILED' THEN 'failed'
                            ELSE pipeline_status
                        END
                        WHERE COALESCE(pipeline_status, '') IN ('', 'ingested')
                          AND status IN (
                            'EXTRACTED', 'ENRICHED', 'MATCHED', 'ACTIONED',
                            'AI_FALLBACK', 'FAILED'
                          )
                        """
                    )
                )


def init_db() -> None:
    """Create tables if they do not exist. Alembic is preferred in production."""
    # Imported here to register models on Base.metadata.
    from app import models  # noqa: F401

    from pathlib import Path

    settings = get_settings()
    if settings.is_sqlite:
        db_path = settings.database_url.replace("sqlite:///", "")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    Base.metadata.create_all(bind=engine)
    if settings.is_sqlite and ":memory:" not in settings.database_url:
        from app.utils.file_perms import restrict_private_file

        restrict_private_file(Path(db_path))
    _upgrade_existing_schema()
    from app.services.ai_marks import clear_unconfigured_ai_marks

    clear_unconfigured_ai_marks()
