"""Interactive pipeline debugger — step-by-step CVE processing trace.

Temporary learning tool: shows which module/function handles each stage
when a CVE ID (and optional sample text) is run from the Debug page.
"""

from __future__ import annotations

import time
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.config import get_settings
from app.integrations.ai_copilot import AICopilot
from app.integrations.epss import EPSSClient
from app.integrations.nvd import NVDClient
from app.models.enums import PipelineStatus
from app.models.vulnerability import Vulnerability
from app.pipeline.step3_enrich import apply_ai_enrichment, inventory_context
from app.pipeline.step4_match import _local_matches, _upsert_match, match_local_assets
from app.services.intel_sources import lookup_active
from app.services.inventory_sources import list_source_specs
from app.utils.cve import CVE_REGEX, extract_cves, priority_from_scores, severity_from_cvss
from app.utils.intel_window import allow_cve
from app.utils.jsonutil import jsonable


@dataclass
class DebugStep:
    step: int
    title: str
    status: str  # ok | fail | skip | warn | info
    module: str
    function: str
    summary: str
    detail: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0


def _now_ms() -> float:
    return time.perf_counter() * 1000


def _step(
    steps: list[DebugStep],
    *,
    step: int,
    title: str,
    status: str,
    module: str,
    function: str,
    summary: str,
    detail: dict[str, Any] | None = None,
    started: float | None = None,
) -> None:
    steps.append(
        DebugStep(
            step=step,
            title=title,
            status=status,
            module=module,
            function=function,
            summary=summary,
            detail=detail or {},
            duration_ms=int(_now_ms() - started) if started is not None else 0,
        )
    )


async def run_cve_debug(
    db: Session,
    *,
    cve_id: str,
    sample_text: str = "",
    persist: bool = True,
) -> dict[str, Any]:
    settings = get_settings()
    steps: list[DebugStep] = []
    raw_input = (sample_text or "").strip()
    cve_input = (cve_id or "").strip().upper().replace("–", "-").replace("—", "-")
    stopped = False
    result: dict[str, Any] = {
        "cve_id": cve_input or None,
        "relevant": False,
        "persisted": False,
        "enrichment": {},
        "matches": [],
    }

    # ------------------------------------------------------------------ 1. REGEX
    t0 = _now_ms()
    haystack = raw_input if raw_input else cve_input
    pattern = CVE_REGEX.pattern
    regex_hits = extract_cves(haystack)
    _step(
        steps,
        step=1,
        title="REGEX scan",
        status="ok" if regex_hits or cve_input else "fail",
        module="app.utils.cve",
        function="extract_cves / CVE_REGEX",
        summary=(
            f"Pattern `{pattern}` scanned "
            + ("sample text" if raw_input else "CVE input field")
            + f" → {len(regex_hits)} hit(s)."
        ),
        detail={
            "pattern": pattern,
            "input_preview": haystack[:400],
            "matches": regex_hits,
            "code_path": "app/utils/cve.py → extract_cves()",
        },
        started=t0,
    )

    # ------------------------------------------------------------------ 2. CVE ID
    t0 = _now_ms()
    detected = cve_input if cve_input.startswith("CVE-") else (regex_hits[0] if regex_hits else "")
    if cve_input and cve_input not in regex_hits and CVE_REGEX.fullmatch(cve_input):
        detected = cve_input
    elif cve_input and regex_hits and cve_input in regex_hits:
        detected = cve_input
    elif not detected and cve_input:
        detected = cve_input if CVE_REGEX.search(cve_input) else ""

    if not detected or not CVE_REGEX.fullmatch(detected):
        # try normalize from loose input
        found = extract_cves(detected or cve_input)
        detected = found[0] if found else ""

    if not detected:
        _step(
            steps,
            step=2,
            title="CVE identifier detection",
            status="fail",
            module="app.utils.cve",
            function="extract_cves",
            summary="No valid CVE-YYYY-NNNN ID could be identified. Pipeline stopped.",
            detail={"cve_input": cve_input, "regex_hits": regex_hits},
            started=t0,
        )
        return {"ok": False, "stopped_at": 2, "steps": [asdict(s) for s in steps], **result}

    result["cve_id"] = detected
    window_ok = allow_cve(detected)
    _step(
        steps,
        step=2,
        title="CVE identifier detection",
        status="ok" if window_ok else "warn",
        module="app.utils.cve + app.utils.intel_window",
        function="extract_cves / allow_cve",
        summary=(
            f"Identified `{detected}`."
            + (
                f" Within INTEL_START_DATE window ({settings.intel_start_date})."
                if window_ok
                else f" Outside INTEL_START_DATE ({settings.intel_start_date}) — would be skipped in normal ingest."
            )
        ),
        detail={
            "cve_id": detected,
            "intel_start_date": settings.intel_start_date,
            "allow_cve": window_ok,
            "code_path": "app/utils/cve.py → extract_cves(); app/utils/intel_window.py → allow_cve()",
        },
        started=t0,
    )

    # Ensure vulnerability row for tracking
    vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == detected).one_or_none()
    created = False
    if persist:
        if vuln is None:
            vuln = Vulnerability(
                cve_id=detected,
                title=detected,
                description="",
                pipeline_status="enriching",
                status=PipelineStatus.ENRICHED,
            )
            db.add(vuln)
            db.flush()
            created = True
        result["persisted"] = True

    # ------------------------------------------------------------------ 3. Static enrichment
    t0 = _now_ms()
    nvd_ok = False
    epss_ok = False
    nvd_error = None
    epss_error = None
    nvd_data: dict[str, Any] | None = None
    epss_data: dict[str, Any] | None = None
    sources_tried: list[dict[str, Any]] = []
    skip_enrichment = not settings.enrichment_enabled

    if skip_enrichment:
        if vuln is not None:
            if not vuln.severity or vuln.severity == "UNKNOWN":
                vuln.severity = severity_from_cvss(vuln.cvss_score)
            vuln.priority = priority_from_scores(vuln.cvss_score, vuln.epss_score)
        _step(
            steps,
            step=3,
            title="Static internet enrichment",
            status="skip",
            module="app.pipeline.step3_enrich",
            function="enrich_cve",
            summary="Enrichment stage is disabled — using ingested fields and continuing to matching.",
            detail={
                "enrichment_enabled": False,
                "vendor": getattr(vuln, "vendor", None) if vuln else None,
                "product": getattr(vuln, "product", None) if vuln else None,
                "cvss": getattr(vuln, "cvss_score", None) if vuln else None,
                "code_path": "Settings → Enrichment → Disable",
            },
            started=t0,
        )
        result["enrichment"] = {
            "skipped": True,
            "nvd_ok": False,
            "epss_ok": False,
            "vendor": getattr(vuln, "vendor", None) if vuln else None,
            "product": getattr(vuln, "product", None) if vuln else None,
        }
        t0 = _now_ms()
        _step(
            steps,
            step=4,
            title="Enrichment source failures",
            status="skip",
            module="app.config + Settings (Internet intel)",
            function="get_settings → enrichment_enabled",
            summary="NVD and EPSS were not called because enrichment is disabled.",
            detail={"enrichment_enabled": False, "code_path": "Settings → Enrichment tab"},
            started=t0,
        )
        t0 = _now_ms()
        _step(
            steps,
            step=5,
            title="AI ticket description",
            status="skip",
            module="app.integrations.ai_copilot",
            function="AICopilot.enrich",
            summary="AI enrichment skipped — enrichment stage is disabled.",
            detail={"enrichment_enabled": False},
            started=t0,
        )
        if vuln is not None:
            result["enrichment"].update(
                {
                    "vendor": vuln.vendor,
                    "product": vuln.product,
                    "ai_used": False,
                    "severity": vuln.severity,
                    "priority": vuln.priority,
                }
            )
    elif not lookup_active("nvd"):
        sources_tried.append(
            {
                "source": "NVD",
                "module": "app.integrations.nvd.NVDClient.fetch",
                "configured": False,
                "ok": False,
                "detail": "NVD lookup is disabled",
            }
        )
    else:
        try:
            nvd_data = await NVDClient().fetch(detected)
            nvd_ok = bool(nvd_data)
            sources_tried.append(
                {
                    "source": "NVD",
                    "module": "app.integrations.nvd.NVDClient.fetch",
                    "configured": True,
                    "ok": nvd_ok,
                    "detail": None if nvd_ok else "Empty / not found",
                }
            )
        except Exception as exc:
            nvd_error = str(exc)
            sources_tried.append(
                {
                    "source": "NVD",
                    "module": "app.integrations.nvd.NVDClient.fetch",
                    "configured": True,
                    "ok": False,
                    "detail": nvd_error,
                }
            )

    if skip_enrichment:
        pass
    elif not lookup_active("epss"):
        sources_tried.append(
            {
                "source": "EPSS",
                "module": "app.integrations.epss.EPSSClient.fetch",
                "configured": False,
                "ok": False,
                "detail": "EPSS lookup is disabled",
            }
        )
    else:
        try:
            epss_data = await EPSSClient().fetch(detected)
            epss_ok = bool(epss_data)
            sources_tried.append(
                {
                    "source": "EPSS",
                    "module": "app.integrations.epss.EPSSClient.fetch",
                    "configured": True,
                    "ok": epss_ok,
                    "detail": None if epss_ok else "Empty / not found",
                }
            )
        except Exception as exc:
            epss_error = str(exc)
            sources_tried.append(
                {
                    "source": "EPSS",
                    "module": "app.integrations.epss.EPSSClient.fetch",
                    "configured": True,
                    "ok": False,
                    "detail": epss_error,
                }
            )

    if not skip_enrichment:
        if vuln is not None and nvd_data:
            from app.pipeline.step3_enrich import _apply_nvd

            _apply_nvd(vuln, nvd_data)
        if vuln is not None and epss_data:
            vuln.epss_score = epss_data.get("epss_score")
            vuln.epss_percentile = epss_data.get("epss_percentile")
            vuln.enrichment = jsonable({**(vuln.enrichment or {}), "epss": epss_data})

        enrich_status = "ok" if (nvd_ok or epss_ok) else (
            "skip" if not lookup_active("nvd") and not lookup_active("epss") else "fail"
        )
        _step(
            steps,
            step=3,
            title="Static internet enrichment",
            status=enrich_status,
            module="app.pipeline.step3_enrich",
            function="enrich_cve → NVDClient.fetch / EPSSClient.fetch",
            summary=(
                f"NVD={'OK' if nvd_ok else 'FAIL'}; EPSS={'OK' if epss_ok else 'FAIL'}."
                + (
                    f" Vendor={getattr(vuln, 'vendor', None) or '—'}, product={getattr(vuln, 'product', None) or '—'}."
                    if vuln
                    else ""
                )
            ),
            detail={
                "nvd_base": settings.nvd_api_base,
                "epss_base": settings.epss_api_base,
                "nvd_ok": nvd_ok,
                "epss_ok": epss_ok,
                "vendor": getattr(vuln, "vendor", None) if vuln else None,
                "product": getattr(vuln, "product", None) if vuln else None,
                "cvss": getattr(vuln, "cvss_score", None) if vuln else None,
                "epss": getattr(vuln, "epss_score", None) if vuln else None,
                "code_path": "app/pipeline/step3_enrich.py → enrich_cve(); app/integrations/nvd.py; app/integrations/epss.py",
            },
            started=t0,
        )
        result["enrichment"] = {
            "nvd_ok": nvd_ok,
            "epss_ok": epss_ok,
            "vendor": getattr(vuln, "vendor", None) if vuln else None,
            "product": getattr(vuln, "product", None) if vuln else None,
        }

        # ------------------------------------------------------------------ 4. Source failures
        t0 = _now_ms()
        failed = [s for s in sources_tried if not s["ok"]]
        _step(
            steps,
            step=4,
            title="Enrichment source failures",
            status="ok" if not failed else ("warn" if (nvd_ok or epss_ok) else "fail"),
            module="app.config + Settings (Internet intel)",
            function="get_settings → nvd_api_base / epss_api_base",
            summary=(
                "All configured internet sources succeeded."
                if not failed
                else f"{len(failed)} source(s) failed or returned empty: "
                + ", ".join(s["source"] for s in failed)
                + "."
            ),
            detail={"sources_tried": sources_tried, "code_path": "Settings → Internet intel tab"},
            started=t0,
        )

        # ------------------------------------------------------------------ 5. AI ticket description
        t0 = _now_ms()
        gaps = []
        if vuln is not None:
            for field_name in ("vendor", "product", "attack_vector", "description"):
                if not getattr(vuln, field_name, None):
                    gaps.append(field_name)

        need_gaps = (not nvd_ok) or bool(gaps)
        ai_configured = settings.ai_configured
        ai_mode = settings.ai_enrichment_mode
        ai_direct = settings.ai_enrichment_direct
        ai_used = False
        ai_raw: dict[str, Any] = {}

        if not ai_configured or not settings.ai_enabled:
            if need_gaps:
                _step(
                    steps,
                    step=5,
                    title="AI ticket description",
                    status="fail",
                    module="app.integrations.ai_copilot",
                    function="AICopilot.enrich (unavailable)",
                    summary=(
                        "Enrichment incomplete and AI module is not configured/enabled. "
                        "Keeping the source description; no plain-language rewrite."
                    ),
                    detail={
                        "gaps": gaps,
                        "ai_enabled": settings.ai_enabled,
                        "ai_configured": ai_configured,
                        "enrichment_mode": ai_mode,
                        "code_path": "Settings → AI modules",
                    },
                    started=t0,
                )
                if not nvd_ok and not epss_ok:
                    stopped = True
                    if vuln is not None and persist:
                        vuln.pipeline_status = "failed"
                        vuln.status = PipelineStatus.FAILED
                        db.commit()
                    return {
                        "ok": False,
                        "stopped_at": 5,
                        "steps": [asdict(s) for s in steps],
                        **result,
                    }
            else:
                _step(
                    steps,
                    step=5,
                    title="AI ticket description",
                    status="skip",
                    module="app.integrations.ai_copilot",
                    function="AICopilot.enrich",
                    summary=(
                        "AI module is not configured. Keeping the NVD/ingest description "
                        "instead of rewriting it for Jira."
                    ),
                    detail={
                        "ai_enabled": settings.ai_enabled,
                        "ai_configured": ai_configured,
                        "enrichment_mode": ai_mode,
                        "provider": settings.ai_provider,
                    },
                    started=t0,
                )
        elif not ai_direct:
            _step(
                steps,
                step=5,
                title="AI ticket description",
                status="skip",
                module="app.integrations.ai_copilot",
                function="AICopilot.enrich",
                summary=(
                    "AI enrichment mode is 'org_llm' — EVulnTasker will not rewrite "
                    "the description. Data is prepared for the organizational LLM only."
                ),
                detail={"enrichment_mode": ai_mode, "gaps": gaps},
                started=t0,
            )
        else:
            try:
                partial = {
                    "vendor": getattr(vuln, "vendor", None),
                    "product": getattr(vuln, "product", None),
                    "description": (getattr(vuln, "description", None) or "")[:4000],
                    "attack_vector": getattr(vuln, "attack_vector", None),
                    "cwe_ids": getattr(vuln, "cwe_ids", None),
                    "inventory": inventory_context(db),
                }
                ai_raw = await AICopilot().enrich(detected, partial)
                filled_fields: list[str] = []
                if vuln is not None:
                    filled_fields = apply_ai_enrichment(vuln, ai_raw)
                    if filled_fields:
                        vuln.ai_enrichment_used = True
                        ai_used = True
                _step(
                    steps,
                    step=5,
                    title="AI ticket description",
                    status="ok",
                    module="app.integrations.ai_copilot",
                    function="AICopilot.enrich",
                    summary=(
                        f"AI rewrote the ticket description via `{settings.ai_provider}` "
                        f"/ `{settings.ai_model}`."
                        if "description" in filled_fields
                        else f"AI ran via `{settings.ai_provider}` / `{settings.ai_model}`."
                    ),
                    detail={
                        "gaps_before": gaps,
                        "filled_fields": filled_fields,
                        "provider": settings.ai_provider,
                        "model": settings.ai_model,
                        "api_base": settings.ai_api_base,
                        "ai_result_keys": list(ai_raw.keys()) if isinstance(ai_raw, dict) else [],
                        "code_path": "app/integrations/ai_copilot.py → AICopilot.enrich()",
                    },
                    started=t0,
                )
            except Exception as exc:
                _step(
                    steps,
                    step=5,
                    title="AI ticket description",
                    status="fail",
                    module="app.integrations.ai_copilot",
                    function="AICopilot.enrich",
                    summary=f"AI description rewrite failed: {exc}",
                    detail={"error": str(exc), "traceback": traceback.format_exc()[-800:]},
                    started=t0,
                )

        if vuln is not None:
            if not vuln.severity or vuln.severity == "UNKNOWN":
                vuln.severity = severity_from_cvss(vuln.cvss_score)
            vuln.priority = priority_from_scores(vuln.cvss_score, vuln.epss_score)
            result["enrichment"].update(
                {
                    "vendor": vuln.vendor,
                    "product": vuln.product,
                    "ai_used": ai_used,
                    "severity": vuln.severity,
                    "priority": vuln.priority,
                }
            )

    # ------------------------------------------------------------------ 6. Cross-match inventory
    t0 = _now_ms()
    match_rows: list[dict[str, Any]] = []
    inventory_specs = list_source_specs(settings)
    vendor = getattr(vuln, "vendor", None) if vuln else None
    product = getattr(vuln, "product", None) if vuln else None

    local_hits = match_local_assets(db, vuln) if vuln else [(a, 0.85) for a in _local_matches(db, vendor, product)]
    for asset, confidence in local_hits:
        if vuln is not None and persist:
            method = asset.source if asset.source in {"csv", "cmdb", "sonatype", "itnm", "local"} else "local"
            _upsert_match(db, vuln, asset, method, confidence)
        match_rows.append(
            {
                "method": getattr(asset, "source", None) or "local",
                "asset": asset.name,
                "system_type": asset.system_type,
                "version": asset.version,
                "team": asset.team,
                "module": "app.pipeline.step4_match.match_local_assets",
            }
        )

    relevant = any(not r.get("error") and r.get("asset") for r in match_rows)
    result["relevant"] = relevant
    result["matches"] = match_rows

    _step(
        steps,
        step=6,
        title="Org inventory cross-match",
        status="ok" if relevant else "warn",
        module="app.pipeline.step4_match",
        function="match_local_assets",
        summary=(
            f"Checked local catalog ({len(local_hits)} hit(s)). "
            + ("Relevant asset(s) found." if relevant else "No organizational relevance in the local catalog.")
        ),
        detail={
            "vendor": vendor,
            "product": product,
            "inventory_sources": [
                {"id": s["id"], "name": s["name"], "enabled": s["enabled"], "role": s["role"]}
                for s in inventory_specs
            ],
            "matches": match_rows,
            "code_path": (
                "app/pipeline/step4_match.py → match_local_assets(); "
                "app/services/inventory_sync.py (catalog refresh)"
            ),
        },
        started=t0,
    )

    # ------------------------------------------------------------------ 7. No relevance tracking
    t0 = _now_ms()
    if relevant:
        if vuln is not None and persist:
            vuln.pipeline_status = "matched"
            vuln.status = PipelineStatus.MATCHED
            db.commit()
        _step(
            steps,
            step=7,
            title="Relevance tracking",
            status="ok",
            module="app.models.asset.AssetMatch",
            function="_upsert_match",
            summary="CVE marked relevant and linked to organizational asset(s). Visible on Asset matching / Org inventory.",
            detail={
                "relevant": True,
                "match_count": len([m for m in match_rows if m.get("asset")]),
                "href": f"/vulnerabilities/{detected}",
                "matching_href": "/matching",
            },
            started=t0,
        )
    else:
        if vuln is not None and persist:
            vuln.pipeline_status = "matched"
            vuln.status = PipelineStatus.MATCHED
            # Store a note for future tracking — no inventing AI ownership in debugger
            notes = (vuln.enrichment or {}) if isinstance(vuln.enrichment, dict) else {}
            notes = {**notes, "debug_no_relevance": {
                "at": datetime.now(timezone.utc).isoformat(),
                "message": "No organizational relevance found during debug run",
                "vendor": vendor,
                "product": product,
            }}
            vuln.enrichment = jsonable(notes)
            db.commit()
        _step(
            steps,
            step=7,
            title="Relevance tracking",
            status="info",
            module="app.models.vulnerability.Vulnerability",
            function="persist unmatched CVE for future tracking",
            summary=(
                f"No relevance in org inventory. CVE `{detected}` "
                + ("stored in local vulnerabilities table for future tracking." if persist else "not persisted.")
            ),
            detail={
                "relevant": False,
                "created": created,
                "persisted": persist and vuln is not None,
                "table": "vulnerabilities",
                "href": f"/vulnerabilities/{detected}" if persist else None,
                "code_path": "app/models/vulnerability.py (local tracking table)",
            },
            started=t0,
        )

    return {
        "ok": True,
        "stopped_at": None if not stopped else 5,
        "cve_id": detected,
        "created": created,
        "relevant": relevant,
        "persisted": result["persisted"],
        "enrichment": result["enrichment"],
        "matches": match_rows,
        "steps": [asdict(s) for s in steps],
        "ran_at": datetime.now(timezone.utc).isoformat(),
    }
