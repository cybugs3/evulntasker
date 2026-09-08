"""
Step 2 — extract CVE / vendor / product from an ingest event.

Deterministic path: regex + labeled-field / CSV / JSON / CPE parsing.
AI fallback: ``AICopilot.extract`` only when regex finds no CVE ID.
Vendor/product gaps are filled later by NVD enrichment (when that stage
is enabled), not counted as extraction AI.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app.integrations.ai_copilot import AICopilot
from app.models.enums import PipelineStatus
from app.models.pipeline import IngestEvent
from app.models.vulnerability import Vulnerability
from app.pipeline.state import begin_step, complete_step, log_ai_fallback, pick
from app.services.intel_parse import parse_intel
from app.utils.cve import extract_cves

log = logging.getLogger(__name__)


@dataclass
class ExtractionResult:
    cve_ids: list[str] = field(default_factory=list)
    vendor: str | None = None
    product: str | None = None
    product_type: str | None = None
    versions: str | None = None
    summary: str | None = None
    ai_used: bool = False
    ai_raw: dict[str, Any] = field(default_factory=dict)
    per_cve: dict[str, dict] = field(default_factory=dict)


def _event_payload(event: IngestEvent) -> Any:
    return pick(event, "payload", "payload", default={}) or {}


def _event_text(event: IngestEvent) -> str:
    chunks: list[str] = []
    raw = pick(event, "raw_text", "raw_text", default="") or ""
    if raw:
        chunks.append(str(raw))
    payload = _event_payload(event)
    if isinstance(payload, dict):
        for key in ("cve", "cve_id", "cveId", "title", "summary", "description", "body", "text"):
            value = payload.get(key)
            if value:
                chunks.append(str(value))
        chunks.append(json.dumps(payload, default=str))
    elif payload:
        chunks.append(str(payload))
    return "\n".join(chunks)


def _payload_cves(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return []
    values: list[str] = []
    for key in ("cve", "cve_id", "cveId", "cves"):
        value = payload.get(key)
        if isinstance(value, list):
            values.extend(str(v) for v in value)
        elif value:
            values.append(str(value))
    found: list[str] = []
    for value in values:
        found.extend(extract_cves(value) or ([value.upper()] if str(value).upper().startswith("CVE-") else []))
    return found


async def extract_from_event(event: IngestEvent, ai_fallback: bool = True) -> ExtractionResult:
    payload = _event_payload(event)
    text = _event_text(event)
    cves = list(dict.fromkeys(_payload_cves(payload) + extract_cves(text)))

    result = ExtractionResult(cve_ids=cves)
    filename = ""
    if isinstance(payload, dict):
        result.vendor = payload.get("vendor")
        result.product = payload.get("product")
        result.summary = payload.get("summary") or payload.get("title")
        result.versions = payload.get("version") or payload.get("versions")
        filename = str(payload.get("filename") or "")
        for row in payload.get("records") or []:
            if not isinstance(row, dict):
                continue
            cve = str(row.get("cve_id") or "").upper()
            if not cve.startswith("CVE-"):
                continue
            result.per_cve[cve] = {
                "vendor": row.get("vendor"),
                "product": row.get("product"),
                "versions": row.get("version") or row.get("versions"),
                "summary": row.get("summary"),
                "cvss_score": row.get("cvss_score") or row.get("cvss"),
                "epss_score": row.get("epss_score") or row.get("epss"),
                "severity": row.get("severity"),
                "attack_vector": row.get("attack_vector") or row.get("attackVector"),
                "cwe_ids": row.get("cwe_ids") or row.get("cwes") or row.get("cwe"),
            }
            if cve not in result.cve_ids:
                result.cve_ids.append(cve)

    for rec in parse_intel(text, filename=filename):
        if rec.cve_id not in result.cve_ids:
            result.cve_ids.append(rec.cve_id)
        current = result.per_cve.get(rec.cve_id, {})
        result.per_cve[rec.cve_id] = {
            "vendor": current.get("vendor") or rec.vendor,
            "product": current.get("product") or rec.product,
            "versions": current.get("versions") or rec.version,
            "summary": current.get("summary") or rec.summary,
        }

    if result.cve_ids:
        first = result.per_cve.get(result.cve_ids[0], {})
        result.vendor = result.vendor or first.get("vendor")
        result.product = result.product or first.get("product")
        result.versions = result.versions or first.get("versions")
        result.summary = result.summary or first.get("summary")
        return result

    if not ai_fallback:
        return result
    copilot = AICopilot()
    if not copilot.available:
        return result
    log.info("event=%s no CVE ID from regex — AI fallback", event.id)
    ai = await copilot.extract(text)
    result.ai_raw = ai if isinstance(ai, dict) else {"raw": ai}
    ai_cves = [
        c.upper()
        for c in (ai.get("cve_ids") or [])
        if isinstance(c, str) and c.upper().startswith("CVE-")
    ]
    for cve in ai_cves:
        if cve not in result.cve_ids:
            result.cve_ids.append(cve)
    result.vendor = result.vendor or ai.get("vendor")
    result.product = result.product or ai.get("product")
    result.product_type = result.product_type or ai.get("product_type")
    result.versions = result.versions or ai.get("versions")
    result.summary = result.summary or ai.get("summary")
    result.ai_used = bool(ai_cves)
    return result


async def finalize_extract(
    db: Session,
    vuln: Vulnerability,
    extracted: ExtractionResult,
    cve_id: str,
) -> None:
    begin_step(db, vuln, PipelineStatus.EXTRACTED, f"Extract started for {cve_id}")
    meta = extracted.per_cve.get(cve_id, {})
    vuln.vendor = vuln.vendor or meta.get("vendor") or extracted.vendor
    vuln.product = vuln.product or meta.get("product") or extracted.product
    vuln.product_type = vuln.product_type or extracted.product_type
    vuln.affected_versions = vuln.affected_versions or meta.get("versions") or extracted.versions
    summary = meta.get("summary") or extracted.summary
    if summary and not vuln.description:
        vuln.description = summary
        vuln.title = vuln.title or summary

    if extracted.ai_used:
        log_ai_fallback(
            db,
            vuln,
            "AI fallback used during extraction",
            {"reasoning": extracted.ai_raw, "cve_ids": extracted.cve_ids},
        )
        vuln.ai_extraction_used = True

    complete_step(
        db,
        vuln,
        PipelineStatus.EXTRACTED,
        f"Extracted {cve_id} vendor={vuln.vendor!s} product={vuln.product!s}",
        {
            "vendor": vuln.vendor,
            "product": vuln.product,
            "versions": vuln.affected_versions,
            "ai_used": extracted.ai_used,
        },
    )
