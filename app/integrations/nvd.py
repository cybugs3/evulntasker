"""NVD CVE 2.0 client — deterministic enrichment source of record."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx
from tenacity import RetryError, retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.config import get_settings
from app.utils.cve import severity_from_cvss
from app.utils.identity import clean_identity, derive_identity

log = logging.getLogger(__name__)

_TRANSIENT = (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError)


def lookup_error_kind(exc: BaseException) -> str:
    if isinstance(exc, RetryError):
        inner = exc.last_attempt.exception()
        return lookup_error_kind(inner) if inner else "lookup_failed"
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    if isinstance(exc, httpx.NetworkError):
        return "unreachable"
    return "lookup_failed"


class NVDClient:
    def __init__(self) -> None:
        self.settings = get_settings()

    async def fetch(self, cve_id: str) -> dict[str, Any] | None:
        data, _error = await self.lookup(cve_id)
        return data

    async def lookup(self, cve_id: str) -> tuple[dict[str, Any] | None, str | None]:
        from app.services.intel_sources import enabled_lookups

        sources = enabled_lookups("nvd")
        if not sources:
            return None, None
        last_error: str | None = None
        for source in sources:
            try:
                parsed = await self._fetch_one(cve_id, source["endpoint"], source.get("api_key") or "")
                if parsed:
                    return parsed, None
            except Exception as exc:
                last_error = lookup_error_kind(exc)
                log.exception("NVD lookup failed for %s via %s (%s)", cve_id, source["endpoint"], last_error)
        return None, last_error

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        retry=retry_if_exception_type(_TRANSIENT),
    )
    async def _fetch_one(self, cve_id: str, endpoint: str, api_key: str) -> dict[str, Any] | None:
        headers = {"User-Agent": "EVulnTasker/1.0"}
        key = api_key or self.settings.nvd_api_key
        if key:
            headers["apiKey"] = key

        params = {"cveId": cve_id}
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(endpoint, params=params, headers=headers)
            if response.status_code == 404:
                return None
            if response.status_code in {403, 429}:
                log.warning(
                    "NVD HTTP %s for %s via %s (rate limit or missing API key)",
                    response.status_code,
                    cve_id,
                    endpoint,
                )
            response.raise_for_status()
            data = response.json()

        items = data.get("vulnerabilities") or []
        if not items:
            return None
        return self._normalize(cve_id, items[0].get("cve") or {})

    def _normalize(self, cve_id: str, cve: dict[str, Any]) -> dict[str, Any]:
        descriptions = cve.get("descriptions") or []
        english = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics") or {}
        cvss_score, cvss_vector, attack_vector, attack_complexity, privs, ui = self._cvss(metrics)

        vendor, product, versions = self._identity(cve)
        vendor = clean_identity(vendor) or None
        product = clean_identity(product) or None
        versions = clean_identity(versions) or None
        if not vendor or not product:
            derived_vendor, derived_product = derive_identity(_short_title(english, cve_id), english)
            vendor = vendor or derived_vendor or None
            product = product or derived_product or None
        cwes = [
            desc.get("value")
            for weakness in cve.get("weaknesses") or []
            for desc in weakness.get("description") or []
            if desc.get("value")
        ]
        published = cve.get("published")
        modified = cve.get("lastModified")

        return {
            "cve_id": cve_id,
            "title": _short_title(english, cve_id),
            "description": english,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "severity": severity_from_cvss(cvss_score),
            "attack_vector": attack_vector,
            "attack_complexity": attack_complexity,
            "privileges_required": privs,
            "user_interaction": ui,
            "vendor": vendor,
            "product": product,
            "affected_versions": versions,
            "cwe_ids": cwes,
            "published_at": _parse_dt(published),
            "nvd_modified_at": _parse_dt(modified),
            "raw": cve,
        }

    def _cvss(self, metrics: dict[str, Any]) -> tuple:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if not entries:
                continue
            data = entries[0].get("cvssData") or {}
            score = data.get("baseScore")
            vector = data.get("vectorString")
            return (
                score,
                vector,
                data.get("attackVector"),
                data.get("attackComplexity"),
                data.get("privilegesRequired"),
                data.get("userInteraction"),
            )
        return None, None, None, None, None, None

    def _identity(self, cve: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
        """Vendor/product from legacy CPE configurations, or the newer NVD `affected` list."""
        vendor, product, versions = self._cpe(cve.get("configurations") or [])
        if vendor or product:
            return vendor, product, versions
        return self._affected(cve.get("affected") or [])

    def _cpe_uri(self, uri: str) -> tuple[str | None, str | None, str | None]:
        parts = (uri or "").split(":")
        if len(parts) >= 6 and parts[0] == "cpe":
            vendor = clean_identity(parts[3].replace("_", " ")) or None
            product = clean_identity(parts[4].replace("_", " ")) or None
            version = parts[5] if parts[5] not in ("*", "-", "") else None
            return vendor, product, version
        return None, None, None

    def _cpe(self, configurations: list[dict[str, Any]]) -> tuple[str | None, str | None, str | None]:
        """Pull the first vendor/product pair from CPE 2.3 URIs."""
        for config in configurations:
            for node in config.get("nodes") or []:
                for match in node.get("cpeMatch") or []:
                    parsed = self._cpe_uri(match.get("criteria") or "")
                    if parsed[0] or parsed[1]:
                        return parsed
        return None, None, None

    def _affected(self, affected: list[Any]) -> tuple[str | None, str | None, str | None]:
        """NVD 2.0 records that no longer ship `configurations` (e.g. CVE-2024-4844)."""
        for block in affected:
            if not isinstance(block, dict):
                continue
            rows = block.get("affectedData") or []
            if not rows and (block.get("vendor") or block.get("product")):
                rows = [block]
            for row in rows:
                if not isinstance(row, dict):
                    continue
                vendor = clean_identity(row.get("vendor")) or None
                product = clean_identity(row.get("product")) or None
                version = None
                for item in row.get("versions") or []:
                    if isinstance(item, dict) and item.get("version"):
                        version = str(item.get("version")).strip() or None
                        break
                if not vendor and not product:
                    for uri in row.get("cpes") or []:
                        vendor, product, version = self._cpe_uri(str(uri))
                        if vendor or product:
                            break
                if vendor or product:
                    return vendor, product, version
        return None, None, None


def _short_title(english: str | None, cve_id: str) -> str:
    """Keep a one-line heading; do not dump the NVD write-up into `title`."""
    skip = {"in the linux kernel, the following vulnerability has been resolved"}
    for raw in (english or "").splitlines():
        line = raw.strip().rstrip(":")
        if not line or line.lower() in skip:
            continue
        if len(line) > 120:
            return line[:117].rstrip() + "…"
        return line
    return cve_id


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
