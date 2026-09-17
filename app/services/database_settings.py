"""Persist and apply the system database URL (SQLite or PostgreSQL)."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import parse_qs, quote_plus, unquote, urlparse

from sqlalchemy import create_engine, text

from app.config import get_settings

SQLITE_DEFAULT = "sqlite:///./data/evulntasker.db"
ENV_KEY = "EVULNTASKER_DATABASE_URL"
LEGACY_ENV_KEY = "VULNINTEL_DATABASE_URL"
DEFAULT_SOCKET = "/var/run/postgresql"
LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def env_path() -> Path:
    return Path(__file__).resolve().parents[2] / ".env"


def is_local_host(host: str, socket: str = "") -> bool:
    if (socket or "").strip():
        return True
    return (host or "").strip().lower() in LOCAL_HOSTS


def build_postgres_url(
    host: str,
    port: int,
    database: str,
    username: str,
    password: str,
    sslmode: str = "prefer",
    socket: str = "",
) -> str:
    user = quote_plus(username or "")
    pwd = quote_plus(password or "")
    auth = f"{user}:{pwd}@" if password else f"{user}@"
    dbname = (database or "evulntasker").strip().lstrip("/")
    socket = (socket or "").strip()
    if socket:
        return f"postgresql+psycopg2://{auth}/{dbname}?host={quote_plus(socket)}"
    mode = sslmode or "prefer"
    return f"postgresql+psycopg2://{auth}{host}:{int(port)}/{dbname}?sslmode={mode}"


def postgres_url_from_mode(
    mode: str,
    *,
    host: str = "",
    port: int = 5432,
    database: str = "evulntasker",
    username: str = "",
    password: str = "",
    sslmode: str = "prefer",
    socket: str = "",
) -> str:
    mode = (mode or "").strip().lower()
    if mode == "local":
        socket = (socket or "").strip()
        host = "" if socket else "127.0.0.1"
        sslmode = "disable"
    return build_postgres_url(
        host=host.strip(),
        port=port,
        database=database,
        username=username,
        password=password,
        sslmode=sslmode,
        socket=socket,
    )


def stored_postgres_password(url: str | None = None) -> str:
    url = url or get_settings().database_url
    if not url or not url.startswith("postgresql"):
        return ""
    parsed = urlparse(url.replace("postgresql+psycopg2://", "postgresql://", 1))
    return unquote(parsed.password or "")


def parse_database_url(url: str | None = None) -> dict:
    settings = get_settings()
    url = url or settings.database_url
    if not url or url.startswith("sqlite"):
        return {
            "enabled": False,
            "mode": "sqlite",
            "backend": "sqlite",
            "host": "",
            "port": 5432,
            "database": "evulntasker",
            "username": "",
            "password_set": False,
            "sslmode": "prefer",
            "socket": "",
            "current_url": url,
        }
    parsed = urlparse(url.replace("postgresql+psycopg2://", "postgresql://", 1))
    query = parse_qs(parsed.query or "")
    socket = ""
    query_host = (query.get("host") or [""])[0]
    if query_host.startswith("/"):
        socket = query_host
    host = parsed.hostname or ""
    mode = "local" if is_local_host(host, socket) else "remote"
    return {
        "enabled": True,
        "mode": mode,
        "backend": "postgresql",
        "host": host or ("127.0.0.1" if mode == "local" else ""),
        "port": parsed.port or 5432,
        "database": (parsed.path or "/evulntasker").lstrip("/"),
        "username": unquote(parsed.username or ""),
        "password_set": bool(parsed.password),
        "sslmode": (query.get("sslmode") or ["prefer"])[0],
        "socket": socket,
        "current_url": _redact(url),
    }


def _redact(url: str) -> str:
    if "://" not in url or "@" not in url:
        return url
    scheme, rest = url.split("://", 1)
    creds, host = rest.split("@", 1)
    if ":" in creds:
        user = creds.split(":", 1)[0]
        return f"{scheme}://{user}:***@{host}"
    return url


def test_postgres_url(url: str) -> dict:
    try:
        engine = create_engine(url, pool_pre_ping=True, future=True)
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "PostgreSQL driver is missing. Install psycopg2-binary in the EVulnTasker venv."
        ) from exc
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"ok": True, "message": "PostgreSQL accepted the connection."}
    finally:
        engine.dispose()


def write_database_url(url: str) -> None:
    path = env_path()
    lines: list[str] = []
    if path.is_file():
        lines = path.read_text(encoding="utf-8").splitlines()
    found_new = False
    found_legacy = False
    out: list[str] = []
    for line in lines:
        if line.startswith(f"{ENV_KEY}=") or line.startswith(f"#{ENV_KEY}="):
            out.append(f"{ENV_KEY}={url}")
            found_new = True
        elif line.startswith(f"{LEGACY_ENV_KEY}=") or line.startswith(f"#{LEGACY_ENV_KEY}="):
            out.append(f"{LEGACY_ENV_KEY}={url}")
            found_legacy = True
        else:
            out.append(line)
    if not found_new:
        if out and out[-1].strip():
            out.append("")
        out.append(f"{ENV_KEY}={url}")
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    os.environ[ENV_KEY] = url
    if found_legacy:
        os.environ[LEGACY_ENV_KEY] = url
    get_settings.cache_clear()


def write_env_values(updates: dict[str, str]) -> None:
    """Create or replace KEY=value lines in .env. Empty values are skipped."""
    clean = {str(key): str(value) for key, value in updates.items() if value is not None and str(value) != ""}
    if not clean:
        return
    path = env_path()
    lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    written: set[str] = set()
    out: list[str] = []
    for line in lines:
        matched = False
        for key, value in clean.items():
            if line.startswith(f"{key}=") or line.startswith(f"#{key}="):
                out.append(f"{key}={value}")
                written.add(key)
                matched = True
                break
        if not matched:
            out.append(line)
    for key, value in clean.items():
        if key not in written:
            if out and out[-1].strip():
                out.append("")
            out.append(f"{key}={value}")
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    os.environ.update(clean)
    get_settings.cache_clear()


def apply_database_url(url: str) -> None:
    """Point the live SQLAlchemy engine at a new URL and create missing tables."""
    write_database_url(url)
    from app.db import session as dbmod

    dbmod.engine.dispose()
    dbmod.engine = dbmod._build_engine()
    dbmod.SessionLocal.configure(bind=dbmod.engine)
    dbmod.init_db()
