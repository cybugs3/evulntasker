"""Sonatype Nexus Lifecycle / IQ catalog teacher.

When the integration is enabled, EVulnTasker lists IQ applications, takes the
latest evaluation report per application, and reads the raw component list
so Internal systems learns both applications and their libraries.

Matching never calls IQ per CVE — only this scheduled / on-connect harvest.
Official endpoints:
  GET /api/v2/applications
  GET /api/v2/reports/applications
  GET /api/v2/applications/{publicId}/reports/{scanId}/raw
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from datetime import datetime
from typing import Any
from urllib.parse import unquote

import httpx

from app.config import get_settings

log = logging.getLogger(__name__)

_USER_AGENT = {"User-Agent": "EVulnTasker/1.0", "Accept": "application/json"}
_STAGE_RANK = {
    "release": 5,
    "stage-release": 4,
    "build": 3,
    "develop": 2,
    "source": 1,
}
_GetJson = Callable[[str], Any]


def _dicts(data: Any, *keys: str) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def _parse_when(value: str | None) -> datetime | None:
    raw = (value or "").strip()
    if not raw:
        return None
    raw = raw.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _ids_from_report(report: dict[str, Any], public_by_internal: dict[str, str]) -> tuple[str, str]:
    public_id = ""
    scan_id = ""
    data_url = str(report.get("reportDataUrl") or "")
    html_url = str(report.get("reportHtmlUrl") or "")
    data_match = re.search(r"applications/([^/]+)/reports/([^/?#]+)", data_url)
    if data_match:
        public_id, scan_id = unquote(data_match.group(1)), data_match.group(2)
    if not (public_id and scan_id):
        html_match = re.search(r"application/([^/]+)/report/([^/?#]+)", html_url)
        if html_match:
            public_id, scan_id = unquote(html_match.group(1)), html_match.group(2)
    internal = str(report.get("applicationId") or "")
    if not public_id and internal:
        public_id = public_by_internal.get(internal, "")
    return public_id, scan_id


def _from_purl(purl: str) -> tuple[str, str, str]:
    value = (purl or "").strip()
    if not value.startswith("pkg:"):
        return "", "", ""
    rest = value[4:].split("?", 1)[0]
    eco, _, path = rest.partition("/")
    if "@" in path:
        name_part, version = path.rsplit("@", 1)
    else:
        name_part, version = path, ""
    name_part = unquote(name_part)
    if "/" in name_part:
        vendor, product = name_part.split("/", 1)
    else:
        vendor, product = eco, name_part
    return vendor.strip(), unquote(product).strip(), unquote(version).strip()


def _component_row(component: dict[str, Any]) -> dict[str, str] | None:
    ident = component.get("componentIdentifier") if isinstance(component.get("componentIdentifier"), dict) else {}
    coords = ident.get("coordinates") if isinstance(ident.get("coordinates"), dict) else {}
    fmt = str(ident.get("format") or "").strip().lower()
    vendor = str(
        coords.get("groupId")
        or coords.get("namespace")
        or coords.get("group")
        or coords.get("organization")
        or ""
    ).strip()
    product = str(
        coords.get("artifactId")
        or coords.get("name")
        or coords.get("packageId")
        or coords.get("id")
        or coords.get("package")
        or ""
    ).strip()
    version = str(coords.get("version") or "").strip()
    if not (vendor and product):
        p_vendor, p_product, p_version = _from_purl(str(component.get("packageUrl") or ""))
        vendor = vendor or p_vendor
        product = product or p_product
        version = version or p_version
    display = str(component.get("displayName") or "").strip()
    if not product:
        product = display
    if not product:
        return None
    if not vendor:
        vendor = fmt or "sonatype"
    external = str(component.get("hash") or component.get("packageUrl") or f"{vendor}:{product}:{version}")
    return {
        "name": (display or product)[:256],
        "vendor": vendor[:128],
        "product": product[:128],
        "product_type": "library",
        "version": version[:64],
        "owner_name": "",
        "owner_username": "",
        "owner_email": "",
        "team": "",
        "environment": "production",
        "external_id": external[:64],
    }


def _application_row(app: dict[str, Any]) -> dict[str, str]:
    name = str(app.get("name") or app.get("publicId") or "application").strip()
    public_id = str(app.get("publicId") or app.get("id") or "").strip()
    return {
        "name": name,
        "vendor": str(app.get("organizationName") or "application").strip() or "application",
        "product": name,
        "product_type": "application",
        "version": "",
        "owner_name": str(app.get("contactUserName") or "").strip(),
        "owner_username": str(app.get("contactUserName") or "").strip(),
        "owner_email": "",
        "team": "",
        "environment": "production",
        "external_id": public_id[:64],
    }


def _pick_latest_reports(reports: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for report in reports:
        app_id = str(report.get("applicationId") or "")
        if not app_id:
            continue
        current = latest.get(app_id)
        if current is None:
            latest[app_id] = report
            continue
        left = _parse_when(str(report.get("evaluationDate") or ""))
        right = _parse_when(str(current.get("evaluationDate") or ""))
        if left and right:
            if left > right:
                latest[app_id] = report
            continue
        left_rank = _STAGE_RANK.get(str(report.get("stage") or "").lower(), 0)
        right_rank = _STAGE_RANK.get(str(current.get("stage") or "").lower(), 0)
        if left_rank >= right_rank:
            latest[app_id] = report
    return latest


class SonatypeClient:
    def __init__(self, conn=None) -> None:
        self.settings = get_settings()
        self.conn = conn or self.settings.sonatype_connection

    def _headers(self) -> dict[str, str]:
        return {**_USER_AGENT, **self.conn.auth_headers()}

    def get_json(self, path: str) -> Any:
        url = self.conn.base_url.rstrip("/") + "/" + path.lstrip("/")
        with httpx.Client(timeout=180.0, verify=self.conn.httpx_verify()) as client:
            response = client.get(url, headers=self._headers(), auth=self.conn.auth_basic())
            response.raise_for_status()
            if not response.content:
                return {}
            return response.json()

    def harvest_catalog(self, *, get_json: _GetJson | None = None) -> list[dict[str, str]]:
        """Applications plus libraries from each application's latest IQ report."""
        if not self.conn.configured:
            return []
        fetch = get_json or self.get_json
        apps = _dicts(fetch("/api/v2/applications"), "applications")
        public_by_internal = {
            str(app.get("id") or ""): str(app.get("publicId") or "")
            for app in apps
            if app.get("id")
        }
        rows: list[dict[str, str]] = []
        seen: set[tuple[str, str, str, str]] = set()

        def add(row: dict[str, str] | None) -> None:
            if not row or not row.get("product"):
                return
            key = (
                row.get("vendor", "").lower(),
                row.get("product", "").lower(),
                row.get("version", "").lower(),
                row.get("product_type", "").lower(),
            )
            if key in seen:
                return
            seen.add(key)
            rows.append(row)

        for app in apps:
            add(_application_row(app))

        try:
            reports = _dicts(fetch("/api/v2/reports/applications"), "reports")
        except Exception:
            log.exception("Sonatype report index failed")
            reports = []
            for app in apps:
                internal = str(app.get("id") or "")
                if not internal:
                    continue
                try:
                    reports.extend(_dicts(fetch(f"/api/v2/reports/applications/{internal}"), "reports"))
                except Exception:
                    log.warning("Sonatype reports failed for application %s", internal)

        for report in _pick_latest_reports(reports).values():
            public_id, scan_id = _ids_from_report(report, public_by_internal)
            if not public_id or not scan_id:
                continue
            try:
                raw = fetch(f"/api/v2/applications/{public_id}/reports/{scan_id}/raw")
            except Exception:
                log.warning("Sonatype raw report failed for %s / %s", public_id, scan_id)
                continue
            for component in _dicts(raw, "components"):
                add(_component_row(component))
        return rows

    async def find(self, vendor: str | None, product: str | None) -> list[dict[str, Any]]:
        """Kept for the connectivity script: list IQ applications (not a CVE-time lookup)."""
        if not self.conn.configured:
            return []
        needle = (product or vendor or "").strip().lower()
        try:
            apps = _dicts(self.get_json("/api/v2/applications"), "applications")
        except Exception:
            log.exception("Sonatype lookup failed")
            return []
        if not needle:
            return apps
        return [
            app
            for app in apps
            if needle in str(app.get("name") or "").lower()
            or needle in str(app.get("publicId") or "").lower()
        ]
