"""Database settings API."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()


class PostgresIn(BaseModel):
    mode: str = "sqlite"
    enabled: bool = False
    host: str = ""
    port: int = Field(default=5432, ge=1, le=65535)
    database: str = "evulntasker"
    username: str = ""
    password: str = ""
    sslmode: str = "prefer"
    socket: str = ""


def _postgres_mode(body: PostgresIn) -> str:
    mode = (body.mode or "").strip().lower()
    if mode in {"sqlite", "local", "remote"}:
        return mode
    return "remote" if body.enabled else "sqlite"


def _postgres_url(body: PostgresIn) -> str:
    from app.services import database_settings as dbs

    mode = _postgres_mode(body)
    if mode == "sqlite":
        return dbs.SQLITE_DEFAULT
    if not body.database or not body.username:
        raise HTTPException(400, "Database name and username are required")
    if mode == "remote" and not body.host.strip():
        raise HTTPException(400, "Host is required for an external PostgreSQL server")
    password = body.password or dbs.stored_postgres_password()
    if mode == "remote" and not password:
        raise HTTPException(400, "Password is required for an external PostgreSQL connection")
    return dbs.postgres_url_from_mode(
        mode,
        host=body.host.strip(),
        port=body.port,
        database=body.database.strip(),
        username=body.username.strip(),
        password=password,
        sslmode=body.sslmode or "prefer",
        socket=body.socket.strip(),
    )


@router.put("/settings/postgres")
def save_postgres(body: PostgresIn) -> dict[str, Any]:
    from app.services import database_settings as dbs

    mode = _postgres_mode(body)
    if mode == "sqlite":
        dbs.apply_database_url(dbs.SQLITE_DEFAULT)
        return {"postgres": dbs.parse_database_url(), "applied": True, "backend": "sqlite", "mode": "sqlite"}
    url = _postgres_url(body)
    try:
        dbs.test_postgres_url(url)
    except Exception as exc:
        raise HTTPException(400, f"PostgreSQL connection failed: {exc}") from exc
    dbs.apply_database_url(url)
    parsed = dbs.parse_database_url()
    return {"postgres": parsed, "applied": True, "backend": "postgresql", "mode": parsed.get("mode") or mode}


@router.post("/settings/postgres/test")
def test_postgres(body: PostgresIn) -> dict[str, Any]:
    from app.services import database_settings as dbs

    mode = _postgres_mode(body)
    if mode == "sqlite":
        return {"ok": True, "message": "SQLite is a local file database; no network test is required."}
    url = _postgres_url(body)
    try:
        return dbs.test_postgres_url(url)
    except Exception as exc:
        raise HTTPException(400, f"PostgreSQL connection failed: {exc}") from exc
