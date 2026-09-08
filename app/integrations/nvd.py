"""NVD CVE 2.0 client — deterministic enrichment source of record."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from app.config import get_settings
from app.utils.cve import severity_from_cvss

log = logging.getLogger(__name__)


class NVDClient:
    def __init__(self) -> None:
        self.settings = get_settings()

    async def fetch(self, cve_id: str) -> dict[str, Any] | None:
        from app.services.intel_sources import enabled_lookups

        sources = enabled_lookups("nvd")
        if not sources:
            return None
        for source in sources:
            parsed = await self._fetch_one(cve_id, source["endpoint"], source.get("api_key") or "")
            if parsed:
                return parsed
        return None

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8))
    async def _fetch_one(self, cve_id: str, endpoint: str, api_key: str) -> dict[str, Any] | None:
        headers = {"User-Agent": "EVulnTasker/1.0"}
        key = api_key or self.settings.nvd_api_key
        if key:
            headers["apiKey"] = key

        params = {"cveId": cve_id}
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(endpoint, params=params, headers=headers)
                if response.status_code == 404:
                    return None
                response.raise_for_status()
                data = response.json()
        except Exception:
            log.exception("NVD lookup failed for %s via %s", cve_id, endpoint)
            return None

        items = data.get("vulnerabilities") or []
        if not items:
            return None
        return self._normalize(cve_id, items[0].get("cve") or {})

    def _normalize(self, cve_id: str, cve: dict[str, Any]) -> dict[str, Any]:
        descriptions = cve.get("descriptions") or []
        english = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics") or {}
        cvss_score, cvss_vector, attack_vector, attack_complexity, privs, ui = self._cvss(metrics)

        vendor, product, versions = self._cpe(cve.get("configurations") or [])
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

    def _cpe(self, configurations: list[dict[str, Any]]) -> tuple[str | None, str | None, str | None]:
        """Pull the first vendor/product pair from CPE 2.3 URIs."""
        for config in configurations:
            for node in config.get("nodes") or []:
                for match in node.get("cpeMatch") or []:
                    uri = match.get("criteria") or ""
                    parts = uri.split(":")
                    if len(parts) >= 6:
                        vendor = parts[3].replace("_", " ")
                        product = parts[4].replace("_", " ")
                        version = parts[5] if parts[5] not in ("*", "-") else None
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
