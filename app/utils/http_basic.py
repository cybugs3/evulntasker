"""Optional HTTP Basic Auth from env — works on port 8080 without TLS."""

from __future__ import annotations

import secrets
from base64 import b64decode

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.config import get_settings


def _credentials() -> tuple[str, str]:
    settings = get_settings()
    user = (getattr(settings, "basic_auth_user", "") or "").strip()
    password = getattr(settings, "basic_auth_password", "") or ""
    return user, password


def is_open_path(path: str) -> bool:
    if path == "/healthz":
        return True
    if path.startswith("/api/webhooks/"):
        return True
    return False


def authorized(header: str, user: str, password: str) -> bool:
    if not header.lower().startswith("basic "):
        return False
    try:
        raw = b64decode(header.split(" ", 1)[1].strip()).decode("utf-8")
    except Exception:
        return False
    if ":" not in raw:
        return False
    given_user, given_password = raw.split(":", 1)
    return secrets.compare_digest(given_user, user) and secrets.compare_digest(
        given_password, password
    )


class OptionalBasicAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        user, password = _credentials()
        if not user or not password:
            return await call_next(request)
        if is_open_path(request.url.path):
            return await call_next(request)
        header = request.headers.get("authorization") or ""
        if authorized(header, user, password):
            return await call_next(request)
        return Response(
            "Authentication required",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="EVulnTasker"'},
        )
