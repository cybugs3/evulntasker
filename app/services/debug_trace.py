"""Interactive pipeline debugger — step-by-step CVE processing trace.

Temporary learning console: walks a CVE through each pipeline stage and
explains what ran, who matched (or why not), and who would be notified.
Debugger never saves records and never sends tickets or mail.
"""

from __future__ import annotations

import asyncio
import time
import traceback
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.config import enabled_ticketing_providers, get_settings
from app.integrations.ai_copilot import AICopilot
from app.integrations.epss import EPSSClient
from app.integrations.gmail import gmail_configured
from app.integrations.nvd import NVDClient
from app.models.asset import Asset
from app.models.enums import PipelineStatus
from app.models.vulnerability import Vulnerability
from app.pipeline.state import apply_status
from app.pipeline.step3_enrich import apply_ai_enrichment, inventory_context
from app.pipeline.step4_match import (
    _direct_hit,
    _has_identity,
    _inventory_count,
    _local_matches,
    _upsert_match,
    is_linux_asset,
    is_linux_cve,
    match_local_assets,
    version_overlap,
)
from app.pipeline.step5_act import _clean_email, _matched_owner_groups
from app.services.intel_sources import lookup_active
from app.services.inventory_sources import list_source_specs
from app.utils.cve import CVE_REGEX, extract_cves, priority_from_scores, severity_from_cvss
from app.utils.identity import identity_for
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
    breakdown: list[str] = field(default_factory=list)


def _now_ms() -> float:
    return time.perf_counter() * 1000


def _append_step(
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
    breakdown: list[str] | None = None,
) -> DebugStep:
    payload = dict(detail or {})
    items = [str(line) for line in (breakdown or payload.get("breakdown") or []) if str(line).strip()]
    if items:
        payload["breakdown"] = items
    item = DebugStep(
        step=step,
        title=title,
        status=status,
        module=module,
        function=function,
        summary=summary,
        detail=payload,
        duration_ms=int(_now_ms() - started) if started is not None else 0,
        breakdown=items,
    )
    steps.append(item)
    return item


def _match_reason(vuln: Vulnerability, asset: Asset) -> str:
    linux_cve = is_linux_cve(vuln)
    family = linux_cve and is_linux_asset(asset)
    direct = _direct_hit(asset, vuln)
    if direct and family:
        return "vendor/product overlap, and Linux kernel CVE vs Linux OS family"
    if family:
        return "Linux kernel CVE vs Linux OS in Internal systems (OS-family match, not the same product name)"
    if direct:
        _keep, bump = version_overlap(asset.version, vuln)
        if bump:
            return "vendor and product overlap with Internal systems, including version overlap"
        return "vendor and product overlap with Internal systems"
    return "inventory matcher accepted this row"


def _no_match_explain(db: Session, vuln: Vulnerability | None) -> tuple[str, list[str]]:
    catalog = _inventory_count(db)
    lines = [
        f"Compared against {catalog} active Internal systems row(s).",
        "Matching reads only Internal systems. CMDB / Sonatype / ITNM teach the catalog; they are not a pipeline match source.",
    ]
    if vuln is None:
        why = "No CVE row existed to compare against the catalog."
        return why, lines + [why]
    vendor, product = identity_for(vuln)
    lines.append(
        f"CVE identity after enrichment: vendor `{vendor or '—'}` / product `{product or '—'}`."
    )
    if catalog == 0:
        why = (
            "No match because Internal systems is empty. Add rows or import a CSV "
            "before a CVE can be relevant to the organization."
        )
        return why, lines + [why]
    if not _has_identity(vuln):
        why = (
            "No match because the CVE has no vendor or product after enrichment, "
            "so there is nothing to compare to catalog names."
        )
        return why, lines + [why]
    linux = is_linux_cve(vuln)
    lines.append(
        "This CVE is treated as a Linux kernel family CVE, so Linux OS rows can match without the same product name."
        if linux
        else "This CVE is not a Linux kernel family CVE, so only vendor+product overlap counts."
    )
    version_blocked: list[str] = []
    for asset in db.query(Asset).filter(Asset.active.is_(True)).all():
        if linux and is_linux_asset(asset):
            continue
        if not _direct_hit(asset, vuln):
            continue
        keep, _bump = version_overlap(asset.version, vuln)
        if keep:
            continue
        label = " ".join(part for part in (asset.vendor, asset.product, asset.version) if part)
        version_blocked.append(label)
    if version_blocked:
        shown = ", ".join(f"`{name}`" for name in version_blocked[:4])
        extra = "" if len(version_blocked) <= 4 else f" (+{len(version_blocked) - 4} more)"
        why = (
            "Vendor and product overlapped Internal systems, but the catalog version "
            f"did not overlap the CVE affected versions: {shown}{extra}."
        )
        return why, lines + [why]
    why = (
        f"No Internal systems row overlapped vendor `{vendor or '—'}` and product `{product or '—'}`"
        + (" and no Linux OS-family row applied." if linux else ".")
    )
    return why, lines + [why]


def _owner_groups_from_assets(assets: list[Asset], fallback_email: str = "") -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    fallback = _clean_email(fallback_email)
    for asset in assets:
        if asset is None or asset.active is False:
            continue
        email = _clean_email(asset.owner_email) or fallback
        if not email:
            continue
        key = email.lower()
        group = groups.get(key)
        if group is None:
            group = {
                "email": email,
                "asset_owner": (asset.owner_name or "").strip() or "Unassigned",
                "username": (asset.owner_username or "").strip() or email.split("@")[0],
                "team": (asset.team or "").strip() or "Unassigned",
                "assets": [],
            }
            groups[key] = group
        group["assets"].append(asset)
        if group["asset_owner"] == "Unassigned" and asset.owner_name:
            group["asset_owner"] = asset.owner_name.strip()
        if group["team"] == "Unassigned" and asset.team:
            group["team"] = asset.team.strip()
    return list(groups.values())


def _ticketing_plan(
    vuln: Vulnerability | None,
    relevant: bool,
    settings: Any,
    matched_assets: list[Asset] | None = None,
) -> dict[str, Any]:
    """Who would be notified on a real ingest. Debugger never sends."""
    providers = enabled_ticketing_providers(settings)
    hunt = _clean_email(getattr(settings, "ticketing_hunt_email", None))
    fallback = _clean_email(getattr(settings, "ticketing_fallback_owner_email", None))
    gmail_on = bool(gmail_configured(settings))
    gmail_to = str(getattr(settings, "gmail_receiver_email", "") or "").strip()
    would: list[dict[str, Any]] = []
    would_not: list[str] = []

    if relevant:
        assets = list(matched_assets or [])
        if not assets and vuln is not None:
            owners = _matched_owner_groups(vuln, fallback)
        else:
            owners = _owner_groups_from_assets(assets, fallback)
        if not owners:
            would_not.append(
                "Owner ticket would not go out: matched Internal systems row(s) have no "
                "owner_email, and Ticketing fallback owner email is blank."
            )
        for group in owners:
            names = [asset.name or asset.product or asset.vendor or "system" for asset in group["assets"]]
            would.append(
                {
                    "kind": "owner",
                    "to": group["email"],
                    "name": group["asset_owner"],
                    "team": group["team"],
                    "systems": names,
                    "via": list(providers),
                }
            )
    else:
        would_not.append(
            "Owner ticket would not go out: no Internal systems match. Matching is required before an owner is notified."
        )

    if providers:
        if hunt:
            would.append(
                {
                    "kind": "hunt",
                    "to": hunt,
                    "name": "Threat hunting",
                    "team": "hunting",
                    "systems": [],
                    "via": list(providers),
                }
            )
        elif "email" in providers:
            would_not.append("Hunt mail would not go out: Permanent hunt email in Settings is blank.")
    else:
        would_not.append("No ticketing provider is enabled in Settings (Jira / Monday / Email / CRM).")

    if gmail_on and gmail_to:
        would.append(
            {
                "kind": "gmail",
                "to": gmail_to,
                "name": "Gmail receiver",
                "team": "",
                "systems": [],
                "via": ["gmail"],
            }
        )

    return {
        "sent": False,
        "providers": providers,
        "gmail_configured": gmail_on,
        "would_notify": would,
        "would_not": would_not,
    }


def _recipient_line(item: dict[str, Any]) -> str:
    kind = item.get("kind") or "recipient"
    to = item.get("to") or "—"
    name = item.get("name") or ""
    team = item.get("team") or ""
    systems = item.get("systems") or []
    via = ", ".join(item.get("via") or []) or "no provider"
    who = f"{name} <{to}>" if name else to
    extra = []
    if team and kind == "owner":
        extra.append(f"team {team}")
    if systems:
        extra.append("systems: " + ", ".join(str(s) for s in systems))
    suffix = f" ({'; '.join(extra)})" if extra else ""
    return f"{kind}: {who}{suffix} via {via}"


async def run_cve_debug(
    db: Session,
    *,
    cve_id: str,
    sample_text: str = "",
    persist: bool = False,
    on_event: Callable[[dict[str, Any]], Any] | None = None,
) -> dict[str, Any]:
    persist = False
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
        "tickets": [],
        "ticketing_plan": {"sent": False, "would_notify": [], "would_not": []},
        "match_lesson": "",
    }

    def _notify(payload: dict[str, Any]) -> None:
        if on_event:
            on_event(jsonable(payload))

    async def begin(step: int, title: str, module: str, function: str) -> float:
        _notify(
            {
                "type": "begin",
                "step": step,
                "title": title,
                "module": module,
                "function": function,
                "status": "run",
                "summary": "Working…",
            }
        )
        await asyncio.sleep(0)
        return _now_ms()

    async def record(_acc: list[DebugStep] | None = None, **kwargs: Any) -> None:
        item = _append_step(steps, **kwargs)
        _notify({"type": "step", **asdict(item)})
        await asyncio.sleep(0)

    # ------------------------------------------------------------------ 1. REGEX
    t0 = await begin(1, "REGEX scan", "app.utils.cve", "extract_cves / CVE_REGEX")
    haystack = raw_input if raw_input else cve_input
    pattern = CVE_REGEX.pattern
    regex_hits = extract_cves(haystack)
    source = "pasted sample text" if raw_input else "the CVE ID field"
    await record(
        steps,
        step=1,
        title="REGEX scan",
        status="ok" if regex_hits or cve_input else "fail",
        module="app.utils.cve",
        function="extract_cves / CVE_REGEX",
        summary=(
            f"Pattern `{pattern}` scanned {source} → {len(regex_hits)} hit(s)."
        ),
        breakdown=[
            f"Scanned {source} with `{pattern}`.",
            f"Found {len(regex_hits)} CVE ID(s): {', '.join(regex_hits) or 'none'}.",
            "This is the same extractor Local TEXT ingest uses before a file is accepted.",
        ],
        detail={
            "pattern": pattern,
            "input_preview": haystack[:400],
            "matches": regex_hits,
            "code_path": "app/utils/cve.py → extract_cves()",
        },
        started=t0,
    )

    # ------------------------------------------------------------------ 2. CVE ID
    t0 = await begin(
        2,
        "CVE identifier detection",
        "app.utils.cve + app.utils.intel_window",
        "extract_cves / allow_cve",
    )
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
        await record(
            steps,
            step=2,
            title="CVE identifier detection",
            status="fail",
            module="app.utils.cve",
            function="extract_cves",
            summary="No valid CVE-YYYY-NNNN ID could be identified. Pipeline stopped.",
            breakdown=[
                "Looked at the CVE ID field and any regex hits from sample text.",
                "None matched CVE-YYYY-NNNN, so enrichment, matching, and ticketing did not run.",
            ],
            detail={"cve_input": cve_input, "regex_hits": regex_hits},
            started=t0,
        )
        return {"ok": False, "stopped_at": 2, "steps": [asdict(s) for s in steps], **result}

    result["cve_id"] = detected
    window_ok = allow_cve(detected)
    if not window_ok:
        await record(
            steps,
            step=2,
            title="CVE identifier detection",
            status="fail",
            module="app.utils.cve + app.utils.intel_window",
            function="extract_cves / allow_cve",
            summary=(
                f"Identified `{detected}`. Outside INTEL_START_DATE "
                f"({settings.intel_start_date}) — ignored."
            ),
            breakdown=[
                f"Identified `{detected}`.",
                f"INTEL_START_DATE is {settings.intel_start_date}.",
                "This ID is older than the window, so ingest — including Debugger — stops here.",
            ],
            detail={
                "cve_id": detected,
                "intel_start_date": settings.intel_start_date,
                "allow_cve": False,
                "code_path": "app/utils/cve.py → extract_cves(); app/utils/intel_window.py → allow_cve()",
            },
            started=t0,
        )
        return {"ok": False, "stopped_at": 2, "steps": [asdict(s) for s in steps], **result}

    await record(
        steps,
        step=2,
        title="CVE identifier detection",
        status="ok",
        module="app.utils.cve + app.utils.intel_window",
        function="extract_cves / allow_cve",
        summary=(
            f"Identified `{detected}`. Within INTEL_START_DATE window ({settings.intel_start_date})."
        ),
        breakdown=[
            f"Identified `{detected}`.",
            f"INTEL_START_DATE window starts {settings.intel_start_date} — this ID is allowed.",
            "A temporary CVE row is used for later stages and rolled back at the end. Debugger never saves it.",
        ],
        detail={
            "cve_id": detected,
            "intel_start_date": settings.intel_start_date,
            "allow_cve": True,
            "code_path": "app/utils/cve.py → extract_cves(); app/utils/intel_window.py → allow_cve()",
        },
        started=t0,
    )

    # Working CVE row so matching and ticketing can run. Persist only commits it.
    vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == detected).one_or_none()
    created = False
    if vuln is None:
        vuln = Vulnerability(
            cve_id=detected,
            title=detected,
            description="",
        )
        apply_status(vuln, PipelineStatus.ENRICHED)
        db.add(vuln)
        db.flush()
        created = True
    result["persisted"] = persist

    # ------------------------------------------------------------------ 3. Static enrichment
    t0 = await begin(
        3,
        "Static internet enrichment",
        "app.pipeline.step3_enrich",
        "enrich_cve → NVDClient.fetch / EPSSClient.fetch",
    )
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
        await record(
            steps,
            step=3,
            title="Static internet enrichment",
            status="skip",
            module="app.pipeline.step3_enrich",
            function="enrich_cve",
            summary="Enrichment stage is disabled — using ingested fields and continuing to matching.",
            breakdown=[
                "Settings → Enrichment is off, so NVD and EPSS were not called.",
                f"Identity used as-is: vendor `{getattr(vuln, 'vendor', None) or '—'}` / product `{getattr(vuln, 'product', None) or '—'}`.",
                "Matching still runs against Internal systems with whatever identity is already on the CVE.",
            ],
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
        t0 = await begin(
            4,
            "Enrichment source failures",
            "app.config + Settings (Enrichment / ATOM feeds)",
            "get_settings → enrichment_enabled",
        )
        await record(
            steps,
            step=4,
            title="Enrichment source failures",
            status="skip",
            module="app.config + Settings (Enrichment / ATOM feeds)",
            function="get_settings → enrichment_enabled",
            summary="NVD and EPSS were not called because enrichment is disabled.",
            breakdown=[
                "Source-failure check is skipped when enrichment is off.",
                "No internet lookup ran, so there is no NVD/EPSS failure to report.",
            ],
            detail={"enrichment_enabled": False, "code_path": "Settings → Enrichment tab"},
            started=t0,
        )
        t0 = await begin(
            5,
            "AI ticket description",
            "app.integrations.ai_copilot",
            "AICopilot.enrich",
        )
        await record(
            steps,
            step=5,
            title="AI ticket description",
            status="skip",
            module="app.integrations.ai_copilot",
            function="AICopilot.enrich",
            summary="AI enrichment skipped — enrichment stage is disabled.",
            breakdown=[
                "AI ticket rewrite only runs after static enrichment.",
                "Because enrichment is disabled, the original description is kept.",
            ],
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
            nvd_data, nvd_kind = await NVDClient().lookup(detected)
            nvd_ok = bool(nvd_data)
            sources_tried.append(
                {
                    "source": "NVD",
                    "module": "app.integrations.nvd.NVDClient.lookup",
                    "configured": True,
                    "ok": nvd_ok,
                    "detail": None
                    if nvd_ok
                    else ("Timed out / unreachable" if nvd_kind in {"timeout", "unreachable"} else "Empty / not found"),
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
            epss_data, epss_kind = await EPSSClient().lookup(detected)
            epss_ok = bool(epss_data)
            sources_tried.append(
                {
                    "source": "EPSS",
                    "module": "app.integrations.epss.EPSSClient.lookup",
                    "configured": True,
                    "ok": epss_ok,
                    "detail": None
                    if epss_ok
                    else ("Timed out / unreachable" if epss_kind in {"timeout", "unreachable"} else "Empty / not found"),
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
        await record(
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
                + (
                    " NVD returned the CVE but no vendor/product (no CPE and no affected[] identity)."
                    if nvd_ok and vuln is not None and not (vuln.vendor or vuln.product)
                    else ""
                )
            ),
            breakdown=[
                f"NVD lookup {'succeeded' if nvd_ok else 'failed or returned empty'}.",
                f"EPSS lookup {'succeeded' if epss_ok else 'failed or returned empty'}.",
                (
                    f"Filled vendor `{getattr(vuln, 'vendor', None) or '—'}` / "
                    f"product `{getattr(vuln, 'product', None) or '—'}` / "
                    f"CVSS {getattr(vuln, 'cvss_score', None) or '—'}."
                    if vuln
                    else "No CVE row to fill."
                ),
                *(
                    [
                        "NVD had the CVE but no CPE/affected identity — matching will have nothing to compare."
                    ]
                    if nvd_ok and vuln is not None and not (vuln.vendor or vuln.product)
                    else []
                ),
            ],
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
        t0 = await begin(
            4,
            "Enrichment source failures",
            "app.config + Settings (Enrichment / ATOM feeds)",
            "get_settings → nvd_api_base / epss_api_base",
        )
        failed = [s for s in sources_tried if not s["ok"]]
        await record(
            steps,
            step=4,
            title="Enrichment source failures",
            status="ok" if not failed else ("warn" if (nvd_ok or epss_ok) else "fail"),
            module="app.config + Settings (Enrichment / ATOM feeds)",
            function="get_settings → nvd_api_base / epss_api_base",
            summary=(
                "All configured internet sources succeeded."
                if not failed
                else f"{len(failed)} source(s) failed or returned empty: "
                + ", ".join(s["source"] for s in failed)
                + "."
            ),
            breakdown=(
                ["Every configured internet source returned data."]
                if not failed
                else [
                    f"{item['source']}: {item.get('detail') or 'empty / not found'}."
                    for item in failed
                ]
            ),
            detail={"sources_tried": sources_tried, "code_path": "Settings → Feeds → ATOM feeds"},
            started=t0,
        )

        # ------------------------------------------------------------------ 5. AI ticket description
        t0 = await begin(
            5,
            "AI ticket description",
            "app.integrations.ai_copilot",
            "AICopilot.enrich",
        )
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
                await record(
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
                    breakdown=[
                        f"Missing after NVD/EPSS: {', '.join(gaps) or 'none'}." if gaps else "NVD lookup failed, so AI would normally fill gaps.",
                        f"AI enabled={settings.ai_enabled}, configured={ai_configured}.",
                        "Without AI, the original source description is kept for later stages.",
                    ],
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
                    if persist:
                        apply_status(vuln, PipelineStatus.FAILED)
                        db.commit()
                    else:
                        db.rollback()
                    return {
                        "ok": False,
                        "stopped_at": 5,
                        "steps": [asdict(s) for s in steps],
                        **result,
                    }
            else:
                await record(
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
                    breakdown=[
                        "NVD/EPSS already filled vendor, product, and description.",
                        "AI rewrite is optional and was skipped because the module is off or unconfigured.",
                    ],
                    detail={
                        "ai_enabled": settings.ai_enabled,
                        "ai_configured": ai_configured,
                        "enrichment_mode": ai_mode,
                        "provider": settings.ai_provider,
                    },
                    started=t0,
                )
        elif not ai_direct:
            await record(
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
                breakdown=[
                    "Settings → AI modules mode is org_llm.",
                    "EVulnTasker does not call a hosted model to rewrite the ticket text.",
                    f"Gaps left for the org LLM: {', '.join(gaps) or 'none'}.",
                ],
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
                await record(
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
                    breakdown=[
                        f"Called `{settings.ai_provider}` / `{settings.ai_model}`.",
                        f"Gaps before AI: {', '.join(gaps) or 'none'}.",
                        f"Fields filled: {', '.join(filled_fields) or 'none'}.",
                    ],
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
                await record(
                    steps,
                    step=5,
                    title="AI ticket description",
                    status="fail",
                    module="app.integrations.ai_copilot",
                    function="AICopilot.enrich",
                    summary=f"AI description rewrite failed: {exc}",
                    breakdown=[
                        "AI was enabled and called, then raised an error.",
                        f"{exc}",
                        "Matching continues with whatever identity NVD/EPSS already filled.",
                    ],
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
    t0 = await begin(
        6,
        "Org inventory cross-match",
        "app.pipeline.step4_match",
        "match_local_assets",
    )
    match_rows: list[dict[str, Any]] = []
    inventory_specs = list_source_specs(settings)
    vendor = getattr(vuln, "vendor", None) if vuln else None
    product = getattr(vuln, "product", None) if vuln else None
    catalog = _inventory_count(db)

    local_hits = match_local_assets(db, vuln) if vuln else [(a, 0.85) for a in _local_matches(db, vendor, product)]
    matched_assets = [asset for asset, _confidence in local_hits]
    match_breakdown: list[str] = [
        f"Read {catalog} active Internal systems row(s).",
        "CMDB / Sonatype / ITNM are inventory teachers only — matching does not call them.",
        f"CVE identity used: vendor `{vendor or '—'}` / product `{product or '—'}`.",
    ]
    for asset, confidence in local_hits:
        method = asset.source if asset.source in {"csv", "cmdb", "sonatype", "itnm", "local"} else "local"
        reason = _match_reason(vuln, asset) if vuln else "name overlap with vendor/product"
        if vuln is not None:
            _upsert_match(db, vuln, asset, method, confidence)
        owner_label = asset.owner_name or asset.owner_email or "no owner on this row"
        match_rows.append(
            {
                "method": getattr(asset, "source", None) or "local",
                "asset": asset.name,
                "system_type": asset.system_type,
                "version": asset.version,
                "vendor": asset.vendor,
                "product": asset.product,
                "team": asset.team,
                "owner_name": asset.owner_name,
                "owner_email": asset.owner_email,
                "reason": reason,
                "confidence": confidence,
                "module": "app.pipeline.step4_match.match_local_assets",
            }
        )
        match_breakdown.append(
            f"Matched `{asset.name}` ({asset.vendor or '—'} / {asset.product or '—'} "
            f"{asset.version or ''}). Why: {reason}. Owner: {owner_label}"
            + (f", team {asset.team}" if asset.team else "")
            + "."
        )
    if local_hits and vuln is not None:
        db.flush()
        db.refresh(vuln, attribute_names=["matches"])

    miss_why = ""
    if not local_hits:
        miss_why, miss_lines = _no_match_explain(db, vuln)
        match_breakdown.extend(miss_lines)

    relevant = any(not r.get("error") and r.get("asset") for r in match_rows)
    result["relevant"] = relevant
    result["matches"] = match_rows
    result["match_lesson"] = (
        "; ".join(f"{row['asset']} ({row.get('reason')})" for row in match_rows if row.get("asset"))
        if relevant
        else miss_why
    )

    await record(
        steps,
        step=6,
        title="Org inventory cross-match",
        status="ok" if relevant else "warn",
        module="app.pipeline.step4_match",
        function="match_local_assets",
        summary=(
            f"Matched {len(local_hits)} Internal systems row(s)."
            if relevant
            else miss_why or "No organizational relevance in Internal systems."
        ),
        breakdown=match_breakdown,
        detail={
            "vendor": vendor,
            "product": product,
            "catalog_size": catalog,
            "why_no_match": miss_why or None,
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

    # ------------------------------------------------------------------ 7. Relevance
    t0 = await begin(
        7,
        "Relevance",
        "app.pipeline.step4_match",
        "match_local_assets",
    )
    plan_preview = _ticketing_plan(vuln, relevant, settings, matched_assets)
    owner_lines = [
        _recipient_line(item) for item in plan_preview["would_notify"] if item.get("kind") == "owner"
    ]
    if relevant:
        apply_status(vuln, PipelineStatus.MATCHED)
        relevance_breakdown = [
            "This CVE is relevant to the organization because Internal systems matched.",
            *[
                f"`{row['asset']}` matched because {row.get('reason')}."
                for row in match_rows
                if row.get("asset")
            ],
            *(
                ["If this were a real ingest, owner ticket(s) would go to:"]
                + owner_lines
                if owner_lines
                else [
                    "If this were a real ingest, no owner ticket would go out — matched rows have no owner_email "
                    "(and no fallback owner email)."
                ]
            ),
        ]
        await record(
            steps,
            step=7,
            title="Relevance",
            status="ok",
            module="app.models.asset.AssetMatch",
            function="_upsert_match",
            summary=(
                f"`{detected}` is relevant. "
                + (
                    "Would notify: " + "; ".join(owner_lines)
                    if owner_lines
                    else "Matched, but no owner_email to notify."
                )
            ),
            breakdown=relevance_breakdown,
            detail={
                "relevant": True,
                "match_count": len([m for m in match_rows if m.get("asset")]),
                "would_notify_owners": owner_lines,
                "matching_href": "/matching",
            },
            started=t0,
        )
    else:
        apply_status(vuln, PipelineStatus.MATCHED)
        await record(
            steps,
            step=7,
            title="Relevance",
            status="info",
            module="app.pipeline.step4_match",
            function="match_local_assets",
            summary=f"`{detected}` is not relevant: {miss_why}",
            breakdown=[
                f"`{detected}` is not relevant to the organization.",
                miss_why or "No Internal systems overlap.",
                "Owner ticket would not go out without a match.",
                "A real ingest can still send hunt mail if Permanent hunt email is set — Debugger never sends it.",
            ],
            detail={
                "relevant": False,
                "created": created,
                "persisted": persist,
                "why": miss_why,
            },
            started=t0,
        )

    # ------------------------------------------------------------------ 8. Ticketing plan (never sent)
    t0 = await begin(
        8,
        "Ticketing",
        "app.pipeline.step5_act",
        "_ticketing_plan",
    )
    plan = _ticketing_plan(vuln, relevant, settings, matched_assets)
    result["ticketing_plan"] = plan
    result["tickets"] = []
    would = plan["would_notify"]
    would_not = plan["would_not"]
    plan_breakdown = [
        "Debugger never opens a ticket, never sends mail, and never calls Jira / Monday / SMTP / Gmail / Exchange.",
        f"Enabled ticketing providers in Settings: {', '.join(plan['providers']) or 'none'}.",
    ]
    if would:
        plan_breakdown.append("If this were a real ingest, notify:")
        plan_breakdown.extend(_recipient_line(item) for item in would)
    plan_breakdown.extend(would_not)

    if would:
        act_status = "ok"
        act_summary = (
            "Nothing sent. Would notify: " + "; ".join(_recipient_line(item) for item in would)
        )
    elif would_not:
        act_status = "info"
        act_summary = "Nothing sent. " + " ".join(would_not)
    else:
        act_status = "skip"
        act_summary = "Nothing sent. No ticketing destination is configured."

    await record(
        steps,
        step=8,
        title="Ticketing",
        status=act_status,
        module="app.pipeline.step5_act",
        function="_ticketing_plan",
        summary=act_summary,
        breakdown=plan_breakdown,
        detail={
            "sent": False,
            "providers": plan["providers"],
            "would_notify": would,
            "would_not": would_not,
            "gmail_configured": plan["gmail_configured"],
            "persisted": persist,
            "audit_log": False,
            "ingest_event": False,
            "code_path": "app/services/debug_trace.py → _ticketing_plan() (no take_action)",
        },
        started=t0,
    )

    db.rollback()
    result["persisted"] = False
    created = False

    return {
        "ok": True,
        "stopped_at": None if not stopped else 5,
        "cve_id": detected,
        "created": created,
        "relevant": relevant,
        "persisted": result["persisted"],
        "enrichment": result["enrichment"],
        "matches": match_rows,
        "match_lesson": result["match_lesson"],
        "tickets": [],
        "ticketing_plan": plan,
        "steps": [asdict(s) for s in steps],
        "ran_at": datetime.now(timezone.utc).isoformat(),
    }
