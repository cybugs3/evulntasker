"""
Step 3 — deterministic enrichment (NVD + EPSS) with AI for ticket language.

NVD/EPSS fill scores and structured fields. When AI enrichment is enabled,
the model rewrites the description into plain language for Jira tickets —
even when NVD already returned a technical write-up.

When enrichment is disabled in Settings, ingested JSON fields are kept and
the pipeline continues to asset matching without NVD, EPSS, or AI calls.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.config import get_settings
from app.integrations.ai_copilot import AICopilot
from app.integrations.epss import EPSSClient
from app.integrations.nvd import NVDClient
from app.models.asset import Asset
from app.models.enums import PipelineStatus
from app.models.vulnerability import Vulnerability
from app.pipeline.state import begin_step, complete_step, log_ai_fallback, set_status, write_audit
from app.utils.cve import priority_from_scores, severity_from_cvss
from app.utils.identity import clean_identity, ensure_identity
from app.utils.jsonutil import jsonable

log = logging.getLogger(__name__)

REQUIRED_FIELDS = ("vendor", "product", "attack_vector", "description")


def _missing(vuln: Vulnerability) -> list[str]:
    missing: list[str] = []
    for field in REQUIRED_FIELDS:
        value = getattr(vuln, field)
        if field in {"vendor", "product"}:
            if not clean_identity(value):
                missing.append(field)
        elif not value:
            missing.append(field)
    return missing


def _intel_lookup_on(feed_type: str, settings: Any) -> bool:
    """Same on/off source as NVDClient/EPSSClient: GUI lookups, then .env flags."""
    if not getattr(settings, "enrichment_enabled", False):
        return False
    try:
        from app.services.intel_sources import lookup_active

        return bool(lookup_active(feed_type))
    except Exception:
        if feed_type == "nvd":
            return bool(getattr(settings, "nvd_configured", False))
        if feed_type == "epss":
            return bool(getattr(settings, "epss_configured", False))
        return False


def enrichment_gaps(vuln: Vulnerability, settings: Any | None = None) -> list[str]:
    """Fields still required from enabled NVD/EPSS lookups before match/act may run."""
    settings = settings or get_settings()
    if not settings.enrichment_enabled:
        return []
    nvd_on = _intel_lookup_on("nvd", settings)
    epss_on = _intel_lookup_on("epss", settings)
    if not nvd_on and not epss_on:
        return []
    missing: list[str] = []
    if nvd_on:
        if not clean_identity(vuln.vendor):
            missing.append("vendor")
        if not clean_identity(vuln.product):
            missing.append("product")
        if vuln.cvss_score is None:
            missing.append("cvss")
    if epss_on and vuln.epss_score is None:
        missing.append("epss")
    return missing


def intel_wait_message(
    needed: list[str],
    nvd_error: str | None = None,
    epss_error: str | None = None,
) -> tuple[str, str]:
    """Return (wait_kind, wait_reason). Timeout stays waiting — never FAILED."""
    timed = []
    if nvd_error in {"timeout", "unreachable"}:
        timed.append("NVD")
    if epss_error in {"timeout", "unreachable"}:
        timed.append("EPSS")
    if timed:
        who = " and ".join(timed)
        return (
            "timeout",
            f"{who} did not respond in time. Matching and tickets wait until NVD/EPSS return full data.",
        )
    missing = ", ".join(needed) or "required fields"
    return (
        "incomplete",
        f"Enrichment is incomplete ({missing}). Matching and tickets wait until NVD/EPSS return full data.",
    )


def is_enrichment_waiting(vuln: Vulnerability | None) -> bool:
    if vuln is None:
        return False
    blob = vuln.enrichment if isinstance(vuln.enrichment, dict) else {}
    return bool(blob.get("waiting")) or (getattr(vuln, "pipeline_status", "") or "") == "waiting_enrichment"


def _next_retry_at(attempts: int, base_seconds: int) -> datetime:
    delay = min(int(max(30, base_seconds) * (2 ** min(max(attempts, 0), 5))), 1800)
    return datetime.now(timezone.utc) + timedelta(seconds=delay)


def due_waiting_enrichment(db: Session, limit: int = 40) -> list[Vulnerability]:
    flagged = (
        db.query(Vulnerability)
        .filter(Vulnerability.pipeline_status == "waiting_enrichment")
        .order_by(Vulnerability.updated_at.asc())
        .limit(limit)
        .all()
    )
    extras: list[Vulnerability] = []
    if len(flagged) < limit:
        seen = {vuln.id for vuln in flagged}
        extras = [
            vuln
            for vuln in (
                db.query(Vulnerability)
                .filter(
                    or_(
                        Vulnerability.status == PipelineStatus.EXTRACTED,
                        Vulnerability.status == PipelineStatus.ENRICHED,
                    ),
                    Vulnerability.pipeline_status != "waiting_enrichment",
                )
                .order_by(Vulnerability.updated_at.asc())
                .limit(limit)
                .all()
            )
            if vuln.id not in seen and is_enrichment_waiting(vuln)
        ]
    rows = flagged + extras
    now = datetime.now(timezone.utc)
    due: list[Vulnerability] = []
    for vuln in rows:
        blob = vuln.enrichment if isinstance(vuln.enrichment, dict) else {}
        raw = blob.get("retry_at")
        if not raw:
            due.append(vuln)
            continue
        try:
            at = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            if at.tzinfo is None:
                at = at.replace(tzinfo=timezone.utc)
        except ValueError:
            due.append(vuln)
            continue
        if at <= now:
            due.append(vuln)
    return due


def _norm_text(value: str | None) -> str:
    return " ".join((value or "").split()).lower()


def _is_plain_rewrite(summary: str, original: str) -> bool:
    """True when the model returned owner-facing text, not a copy of the NVD write-up."""
    if not summary.strip():
        return False
    if _norm_text(summary) == _norm_text(original):
        return False
    preamble = "the following vulnerability has been resolved"
    return not (preamble in _norm_text(summary) and preamble in _norm_text(original))


def _payload_value(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key not in payload:
            continue
        value = payload[key]
        if value is None or value == "":
            continue
        return value
    return None


def _as_float(value: Any) -> float | None:
    if isinstance(value, dict):
        value = (
            value.get("score")
            or value.get("baseScore")
            or value.get("base_score")
            or value.get("cvss_score")
            or value.get("epss")
        )
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        parts = [str(item).strip() for item in value if str(item).strip()]
        return ", ".join(parts) if parts else None
    text = str(value).strip()
    return text or None


def _as_cwes(value: Any) -> list[str] | None:
    if value is None or value == "":
        return None
    if isinstance(value, str):
        return [value.strip()] if value.strip() else None
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            if isinstance(item, dict):
                ident = item.get("id") or item.get("cwe_id") or item.get("cwe")
                if ident:
                    out.append(str(ident))
            elif item:
                out.append(str(item))
        return out or None
    return [str(value)]


def _as_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def inventory_context(db: Session, limit: int = 25) -> list[dict[str, str]]:
    """Compact inventory snapshot so AI can relate the CVE to local systems."""
    rows = (
        db.query(Asset)
        .filter(Asset.active.is_(True))
        .order_by(Asset.id.desc())
        .limit(limit * 2)
        .all()
    )
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for asset in rows:
        key = (
            (asset.vendor or "").strip().lower(),
            (asset.product or "").strip().lower(),
            (asset.version or "").strip().lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "name": asset.name or "",
                "vendor": asset.vendor or "",
                "product": asset.product or "",
                "version": asset.version or "",
            }
        )
        if len(out) >= limit:
            break
    return out


def apply_ai_enrichment(vuln: Vulnerability, ai: dict[str, Any] | None) -> list[str]:
    """Apply AI JSON onto a CVE. Rewrites description when `summary` is present."""
    if not isinstance(ai, dict):
        return []
    filled: list[str] = []

    def fill_str(field: str, *keys: str) -> None:
        current = getattr(vuln, field, None)
        if field in {"vendor", "product", "affected_versions"}:
            if clean_identity(current):
                return
        elif current:
            return
        value = _as_str(_payload_value(ai, *keys))
        if field in {"vendor", "product", "affected_versions"}:
            value = clean_identity(value) or None
        if value:
            setattr(vuln, field, value)
            filled.append(field)

    fill_str("vendor", "vendor")
    fill_str("product", "product")
    fill_str("product_type", "product_type")
    fill_str("affected_versions", "versions", "affected_versions")
    fill_str("attack_vector", "attack_vector")
    if not vuln.cwe_ids:
        cwes = _as_cwes(_payload_value(ai, "cwe_ids", "cwes", "cwe"))
        if cwes:
            vuln.cwe_ids = cwes
            filled.append("cwe_ids")

    blob = dict(vuln.enrichment or {}) if isinstance(vuln.enrichment, dict) else {}
    summary = _as_str(_payload_value(ai, "summary", "description"))
    original = (vuln.description or "").strip()
    if summary and _is_plain_rewrite(summary, original):
        if original and not blob.get("source_description"):
            blob["source_description"] = original
        vuln.description = summary
        filled.append("description")

    vuln.enrichment = jsonable({**blob, "ai": ai})
    flag_modified(vuln, "enrichment")
    return filled


def apply_ingested_fields(vuln: Vulnerability, payload: dict[str, Any] | None) -> list[str]:
    """Copy vendor/product/CVSS/EPSS and related fields from ingest JSON onto the CVE."""
    if not isinstance(payload, dict):
        return []
    applied: list[str] = []

    def set_str(field: str, *keys: str) -> None:
        value = _as_str(_payload_value(payload, *keys))
        if field in {"vendor", "product", "affected_versions"}:
            value = clean_identity(value) or None
        if value:
            setattr(vuln, field, value)
            applied.append(field)

    def set_float(field: str, *keys: str) -> None:
        value = _as_float(_payload_value(payload, *keys))
        if value is not None:
            setattr(vuln, field, value)
            applied.append(field)

    set_str("title", "title")
    set_str("description", "description", "summary")
    set_float("cvss_score", "cvss_score", "cvss", "baseScore", "base_score")
    set_str("cvss_vector", "cvss_vector", "vector_string", "vectorString")
    set_float("epss_score", "epss_score", "epss")
    set_float("epss_percentile", "epss_percentile", "percentile")
    severity = _as_str(_payload_value(payload, "severity"))
    if severity:
        vuln.severity = severity.upper()
        applied.append("severity")
    set_str("attack_vector", "attack_vector", "attackVector")
    set_str("attack_complexity", "attack_complexity", "attackComplexity")
    set_str("privileges_required", "privileges_required", "privilegesRequired")
    set_str("user_interaction", "user_interaction", "userInteraction")
    set_str("vendor", "vendor")
    set_str("product", "product")
    set_str("product_type", "product_type", "productType")
    set_str("affected_versions", "affected_versions", "versions", "version")
    cwes = _as_cwes(_payload_value(payload, "cwe_ids", "cwes", "cwe"))
    if cwes:
        vuln.cwe_ids = cwes
        applied.append("cwe_ids")
    published = _as_datetime(_payload_value(payload, "published_at", "published", "publishedDate"))
    if published:
        vuln.published_at = published
        applied.append("published_at")
    return applied


def _apply_nvd(vuln: Vulnerability, nvd: dict[str, Any]) -> None:
    vuln.title = nvd.get("title") or vuln.title
    vuln.description = nvd.get("description") or vuln.description
    vuln.cvss_score = nvd.get("cvss_score")
    vuln.cvss_vector = nvd.get("cvss_vector")
    vuln.severity = nvd.get("severity") or severity_from_cvss(vuln.cvss_score)
    vuln.attack_vector = nvd.get("attack_vector") or vuln.attack_vector
    vuln.attack_complexity = nvd.get("attack_complexity")
    vuln.privileges_required = nvd.get("privileges_required")
    vuln.user_interaction = nvd.get("user_interaction")
    vuln.vendor = clean_identity(nvd.get("vendor")) or clean_identity(vuln.vendor)
    vuln.product = clean_identity(nvd.get("product")) or clean_identity(vuln.product)
    vuln.affected_versions = clean_identity(nvd.get("affected_versions")) or clean_identity(vuln.affected_versions)
    ensure_identity(vuln)
    vuln.cwe_ids = nvd.get("cwe_ids") or vuln.cwe_ids
    vuln.published_at = nvd.get("published_at") or vuln.published_at
    vuln.nvd_modified_at = nvd.get("nvd_modified_at")
    vuln.enrichment = jsonable(
        {**(vuln.enrichment or {}), "nvd": {k: v for k, v in nvd.items() if k != "raw"}}
    )


def _mark_enrichment_blob(vuln: Vulnerability, **updates: Any) -> None:
    blob = dict(vuln.enrichment or {}) if isinstance(vuln.enrichment, dict) else {}
    blob.update(updates)
    vuln.enrichment = jsonable(blob)
    flag_modified(vuln, "enrichment")


async def enrich_cve(
    db: Session,
    vuln: Vulnerability,
    ai_fallback: bool = True,
    source_fields: dict[str, Any] | None = None,
) -> Vulnerability:
    begin_step(db, vuln, PipelineStatus.ENRICHED, f"Enrichment started for {vuln.cve_id}")
    applied = apply_ingested_fields(vuln, source_fields)
    ensure_identity(vuln)
    nvd_ok = False
    epss_ok = False
    nvd_error: str | None = None
    epss_error: str | None = None
    settings = get_settings()

    if not settings.enrichment_enabled:
        if not vuln.severity or vuln.severity == "UNKNOWN":
            vuln.severity = severity_from_cvss(vuln.cvss_score)
        vuln.priority = priority_from_scores(vuln.cvss_score, vuln.epss_score)
        _mark_enrichment_blob(vuln, skipped=True, skip_reason="enrichment_disabled")
        complete_step(
            db,
            vuln,
            PipelineStatus.ENRICHED,
            "Enrichment skipped — continuing to asset matching",
            {"skipped": True, "applied_fields": applied},
        )
        return vuln

    blob = dict(vuln.enrichment or {}) if isinstance(vuln.enrichment, dict) else {}
    if blob.pop("skipped", None) is not None or blob.pop("skip_reason", None) is not None:
        vuln.enrichment = jsonable(blob)
        flag_modified(vuln, "enrichment")

    if settings.enrichment_enabled:
        if _intel_lookup_on("nvd", settings):
            nvd, nvd_error = await NVDClient().lookup(vuln.cve_id)
            if nvd:
                _apply_nvd(vuln, nvd)
                nvd_ok = True
                nvd_error = None

        if _intel_lookup_on("epss", settings):
            epss, epss_error = await EPSSClient().lookup(vuln.cve_id)
            if epss:
                vuln.epss_score = epss.get("epss_score")
                vuln.epss_percentile = epss.get("epss_percentile")
                vuln.enrichment = jsonable({**(vuln.enrichment or {}), "epss": epss})
                epss_ok = True
                epss_error = None

    gaps = _missing(vuln)
    use_ai_enrich = ai_fallback and settings.ai_enrichment_direct and settings.ai_configured
    if use_ai_enrich:
        log.info(
            "%s AI enrichment — rewriting ticket description (gaps=%s nvd_ok=%s)",
            vuln.cve_id,
            gaps,
            nvd_ok,
        )
        partial = {
            "vendor": vuln.vendor,
            "product": vuln.product,
            "product_type": vuln.product_type,
            "versions": vuln.affected_versions,
            "description": (vuln.description or "")[:4000],
            "attack_vector": vuln.attack_vector,
            "cwe_ids": vuln.cwe_ids,
            "cvss_score": vuln.cvss_score,
            "epss_score": vuln.epss_score,
            "inventory": inventory_context(db),
        }
        ai = await AICopilot().enrich(vuln.cve_id, partial)
        filled_fields = apply_ai_enrichment(vuln, ai)
        if filled_fields:
            vuln.ai_enrichment_used = True
            log_ai_fallback(
                db,
                vuln,
                "AI wrote a plain-language description for owner tickets",
                {
                    "gaps": gaps,
                    "nvd_ok": nvd_ok,
                    "epss_ok": epss_ok,
                    "filled_fields": filled_fields,
                    "reasoning": ai,
                },
            )

    if not vuln.severity or vuln.severity == "UNKNOWN":
        vuln.severity = severity_from_cvss(vuln.cvss_score)
    vuln.priority = priority_from_scores(vuln.cvss_score, vuln.epss_score)

    needed = enrichment_gaps(vuln, settings)
    if needed:
        blob = dict(vuln.enrichment or {}) if isinstance(vuln.enrichment, dict) else {}
        attempts = int(blob.get("attempts") or 0) + 1
        retry_at = _next_retry_at(attempts - 1, getattr(settings, "enrichment_retry_seconds", 120))
        wait_kind, wait_reason = intel_wait_message(needed, nvd_error, epss_error)
        _mark_enrichment_blob(
            vuln,
            waiting=True,
            wait_kind=wait_kind,
            wait_reason=wait_reason,
            missing=needed,
            retry_at=retry_at.isoformat(),
            attempts=attempts,
            last_attempt_at=datetime.now(timezone.utc).isoformat(),
            nvd_error=nvd_error,
            epss_error=epss_error,
        )
        set_status(db, vuln, PipelineStatus.ENRICHED, waiting=True)
        write_audit(
            db,
            vuln,
            PipelineStatus.ENRICHED,
            f"{wait_reason} Missing: {', '.join(needed)}. Retry at {retry_at.isoformat()}",
            {
                "waiting": True,
                "wait_kind": wait_kind,
                "missing": needed,
                "retry_at": retry_at.isoformat(),
                "attempts": attempts,
                "nvd_ok": nvd_ok,
                "epss_ok": epss_ok,
                "nvd_error": nvd_error,
                "epss_error": epss_error,
            },
        )
        db.commit()
        log.info("%s enrichment waiting (%s) for %s — retry at %s", vuln.cve_id, wait_kind, needed, retry_at.isoformat())
        return vuln

    blob = dict(vuln.enrichment or {}) if isinstance(vuln.enrichment, dict) else {}
    for key in (
        "waiting",
        "wait_reason",
        "wait_kind",
        "missing",
        "retry_at",
        "attempts",
        "last_attempt_at",
        "nvd_error",
        "epss_error",
    ):
        blob.pop(key, None)
    if blob != (vuln.enrichment or {}):
        vuln.enrichment = jsonable(blob)
        flag_modified(vuln, "enrichment")

    complete_step(
        db,
        vuln,
        PipelineStatus.ENRICHED,
        "NVD/EPSS enrichment completed"
        + (" with AI ticket description" if vuln.ai_enrichment_used else ""),
        {"nvd_ok": nvd_ok, "epss_ok": epss_ok, "gaps": gaps, "ai_used": bool(vuln.ai_enrichment_used)},
    )
    return vuln
