"""Skip CVEs published before the configured start date."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from app.config import get_settings

NVD_MAX_DAYS = 119


def intel_start() -> datetime | None:
    raw = (getattr(get_settings(), "intel_start_date", "") or "").strip()
    if not raw:
        return None
    try:
        if "T" in raw:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        else:
            dt = datetime.strptime(raw[:10], "%Y-%m-%d")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def cve_year(cve_id: str) -> int | None:
    parts = (cve_id or "").upper().split("-")
    if len(parts) >= 2 and parts[1].isdigit():
        year = int(parts[1])
        if 1999 <= year <= 2100:
            return year
    return None


def parse_published(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def allow_cve(cve_id: str, published: datetime | None = None) -> bool:
    start = intel_start()
    if start is None:
        return True
    if published is not None:
        pub = published if published.tzinfo else published.replace(tzinfo=timezone.utc)
        return pub >= start
    year = cve_year(cve_id)
    if year is None:
        return True
    return year >= start.year


def filter_cves(cves: list[str], published: datetime | None = None) -> list[str]:
    return [cve for cve in cves if allow_cve(cve, published)]


def nvd_lastmod_range() -> tuple[str, str]:
    end = datetime.now(timezone.utc)
    start = intel_start() or (end - timedelta(days=NVD_MAX_DAYS))
    window_start = max(start, end - timedelta(days=NVD_MAX_DAYS))
    return _nvd_ts(window_start), _nvd_ts(end)


def _nvd_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def apply_nvd_window(url: str) -> str:
    """NVD without a date range returns the catalog from 1999. Bound the query."""
    if "services.nvd.nist.gov" not in (url or "").lower():
        return url
    start, end = nvd_lastmod_range()
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.pop("pubStartDate", None)
    query.pop("pubEndDate", None)
    query["lastModStartDate"] = start
    query["lastModEndDate"] = end
    query.setdefault("resultsPerPage", query.get("resultsPerPage") or "20")
    return urlunparse(parsed._replace(query=urlencode(query)))
