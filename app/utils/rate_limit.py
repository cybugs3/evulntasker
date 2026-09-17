"""In-process POST rate limits for destructive and debug endpoints."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# path -> (max hits, window seconds)
LIMITS: dict[str, tuple[int, int]] = {
    "/api/settings/wipe-cve-data": (3, 600),
    "/api/settings/reset-system": (3, 600),
    "/api/settings/reset-internal-systems": (3, 600),
    "/api/debug/run": (20, 60),
    "/api/debug/run/stream": (20, 60),
}

_hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)


def allow(path: str, client: str, *, now: float | None = None) -> bool:
    spec = LIMITS.get(path)
    if spec is None:
        return True
    max_hits, window = spec
    stamp = now if now is not None else time.monotonic()
    key = (client, path)
    bucket = _hits[key]
    cutoff = stamp - window
    while bucket and bucket[0] <= cutoff:
        bucket.popleft()
    if len(bucket) >= max_hits:
        return False
    bucket.append(stamp)
    return True


def reset_limits() -> None:
    _hits.clear()


class SensitivePostLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method == "POST" and request.url.path in LIMITS:
            client = request.client.host if request.client else "unknown"
            if not allow(request.url.path, client):
                return JSONResponse(
                    {"detail": "Too many requests. Wait and try again."},
                    status_code=429,
                )
        return await call_next(request)
