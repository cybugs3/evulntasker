"""Build integration base URLs and httpx client options from host/port/TLS settings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class IntegrationConnection:
    enabled: bool = False
    host: str = ""
    port: int = 443
    use_tls: bool = True
    ignore_cert: bool = False
    username: str = ""
    password: str = ""
    api_path: str = ""
    legacy_url: str = ""

    @property
    def base_url(self) -> str:
        if self.legacy_url:
            return self.legacy_url.rstrip("/")
        host = (self.host or "").strip()
        if not host:
            return ""
        scheme = "https" if self.use_tls else "http"
        default_port = 443 if self.use_tls else 80
        port = int(self.port or default_port)
        port_suffix = "" if port == default_port else f":{port}"
        path = (self.api_path or "").strip()
        if path and not path.startswith("/"):
            path = f"/{path}"
        return f"{scheme}://{host}{port_suffix}{path}".rstrip("/")

    @property
    def configured(self) -> bool:
        return self.enabled and bool(self.base_url)

    def httpx_verify(self) -> bool | str:
        return False if self.ignore_cert else True

    def auth_headers(self) -> dict[str, str]:
        if self.password and "@" not in self.password:
            return {"Authorization": f"Bearer {self.password}"}
        return {}

    def auth_basic(self) -> tuple[str, str] | None:
        if self.username:
            return (self.username, self.password or "")
        return None


def build_integration_url(
    host: str,
    port: int,
    *,
    use_tls: bool = True,
    api_path: str = "",
) -> str:
    return IntegrationConnection(
        host=host,
        port=port,
        use_tls=use_tls,
        api_path=api_path,
    ).base_url


async def probe_connection(conn: IntegrationConnection, path: str = "/") -> dict[str, Any]:
    """Lightweight GET to verify host/port/TLS/credentials."""
    base = conn.base_url
    if not base:
        raise ValueError("Host or URL is required")
    url = f"{base.rstrip('/')}/{path.lstrip('/')}"
    from app.utils.outbound_url import assert_http_url

    assert_http_url(url)
    headers = {"User-Agent": "EVulnTasker/1.0", "Accept": "application/json", **conn.auth_headers()}
    auth = conn.auth_basic()
    async with httpx.AsyncClient(timeout=20.0, verify=conn.httpx_verify()) as client:
        response = await client.get(url, headers=headers, auth=auth)
        return {"ok": True, "status": response.status_code, "url": url, "bytes": len(response.content)}
