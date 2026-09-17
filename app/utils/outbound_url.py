"""Guard operator-supplied URLs so the host is not used as an open proxy."""

from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import urlparse

_BLOCKED_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.google.com",
    "instance-data",
}


class OutboundUrlError(ValueError):
    """Raised when a URL is not safe to fetch from this host."""


def assert_http_url(raw: str) -> str:
    """Allow only http/https URLs. Block cloud metadata and link-local targets."""
    url = (raw or "").strip()
    if not url:
        raise OutboundUrlError("URL is required")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise OutboundUrlError("Only http and https URLs are allowed")
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise OutboundUrlError("URL host is required")
    if host in _BLOCKED_HOSTS:
        raise OutboundUrlError("That host is not allowed")
    try:
        address = ip_address(host)
    except ValueError:
        return url
    if address.is_unspecified or address.is_multicast or address.is_link_local:
        raise OutboundUrlError("That address is not allowed")
    return url
