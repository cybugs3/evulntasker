"""Live pipeline workflow: which station a CVE is on, and which it has passed."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session, joinedload

from app.models.asset import AssetMatch
from app.models.enums import PipelineStatus
from app.models.jira import JiraTicket
from app.models.pipeline import IngestEvent, PipelineRun
from app.models.source import InputSource
from app.models.vulnerability import Vulnerability

WORKFLOW_STATIONS = (
    {"id": "ingest", "title": "Ingest"},
    {"id": "extract", "title": "Extraction"},
    {"id": "enrich", "title": "Enrichment"},
    {"id": "match", "title": "Matching"},
    {"id": "act", "title": "Actions"},
)

STATION_IDS = tuple(item["id"] for item in WORKFLOW_STATIONS)

_STATUS_INDEX = {
    "ingested": 0,
    "extracting": 1,
    "extracted": 1,
    "enriching": 2,
    "waiting_enrichment": 2,
    "enriched": 2,
    "ai_fallback": 2,
    "matching": 3,
    "matched": 3,
    "acting": 4,
    "completed": 5,
    "actioned": 5,
    "duplicate": 0,
}

_ENUM_TO_PIPELINE = {
    "INGESTED": "ingested",
    "EXTRACTED": "extracting",
    "ENRICHED": "enriching",
    "MATCHED": "matching",
    "ACTIONED": "completed",
    "AI_FALLBACK": "enriching",
    "FAILED": "failed",
}


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc).isoformat()
    return value.astimezone(timezone.utc).isoformat()


def _has_intel(vuln: Vulnerability) -> bool:
    if getattr(vuln, "cvss_score", None) is not None:
        return True
    if getattr(vuln, "epss_score", None) is not None:
        return True
    blob = getattr(vuln, "enrichment", None) or {}
    return isinstance(blob, dict) and bool(blob.get("nvd") or blob.get("epss"))


def _waiting_intel(vuln: Vulnerability) -> bool:
    blob = getattr(vuln, "enrichment", None) or {}
    return (isinstance(blob, dict) and bool(blob.get("waiting"))) or (
        getattr(vuln, "pipeline_status", "") or ""
    ) == "waiting_enrichment"


def _enrich_skipped(vuln: Vulnerability) -> bool:
    blob = getattr(vuln, "enrichment", None) or {}
    return isinstance(blob, dict) and bool(blob.get("skipped"))


def _effective_pipeline_status(vuln: Vulnerability) -> str:
    """Use the further-along of pipeline_status and status so drifted rows still classify."""
    raw = (getattr(vuln, "pipeline_status", None) or "").strip().lower()
    status = getattr(vuln, "status", None)
    if isinstance(status, PipelineStatus):
        enum_val = status.value
    else:
        enum_val = str(status or "").strip()
    from_enum = _ENUM_TO_PIPELINE.get(enum_val.upper(), "")
    if (getattr(vuln, "pipeline_status", "") or "") == "waiting_enrichment":
        return "waiting_enrichment"
    raw_i = _STATUS_INDEX.get(raw, -1)
    enum_i = _STATUS_INDEX.get(from_enum, -1)
    if enum_i > raw_i:
        return from_enum or raw or "ingested"
    return raw or from_enum or "ingested"


def canonical_pipeline_status(vuln: Vulnerability) -> str:
    """Compatibility string for APIs. Live Workflow still classifies from this plus intel/match/ticket flags."""
    return _effective_pipeline_status(vuln)


def progress_for_vuln(
    vuln: Vulnerability,
    *,
    has_match: bool = False,
    has_ticket: bool = False,
) -> dict[str, Any]:
    """Live Workflow station flags for one CVE — the system source of truth."""
    progress = workflow_progress(
        _effective_pipeline_status(vuln),
        has_intel=_has_intel(vuln),
        waiting_intel=_waiting_intel(vuln),
        has_match=has_match,
        has_ticket=has_ticket,
        enrich_skipped=_enrich_skipped(vuln),
    )
    blob = getattr(vuln, "enrichment", None) or {}
    if progress.get("waiting") and isinstance(blob, dict):
        progress["wait_reason"] = str(blob.get("wait_reason") or "")
        progress["retry_at"] = str(blob.get("retry_at") or "")
        progress["wait_kind"] = str(blob.get("wait_kind") or "")
    return progress


def reached_enrichment(progress: dict[str, Any]) -> bool:
    return bool(
        progress.get("waiting")
        or progress.get("current") == "enrich"
        or "extract" in (progress.get("done") or [])
        or "enrich" in (progress.get("done") or [])
    )


def reached_matching(progress: dict[str, Any]) -> bool:
    return bool(
        progress.get("unmatched")
        or progress.get("current") == "match"
        or "match" in (progress.get("done") or [])
        or progress.get("column") == "act"
    )


def reached_actions(progress: dict[str, Any]) -> bool:
    return bool(
        progress.get("current") == "act"
        or "act" in (progress.get("done") or [])
        or (progress.get("column") == "act" and not progress.get("unmatched"))
    )


def workflow_progress(
    pipeline_status: str,
    *,
    has_intel: bool = False,
    waiting_intel: bool = False,
    has_match: bool = False,
    has_ticket: bool = False,
    enrich_skipped: bool = False,
) -> dict[str, Any]:
    """Return done stations, the live station, and which column to park the CVE on."""
    raw = (pipeline_status or "ingested").strip().lower()
    failed = raw == "failed"
    cursor = _STATUS_INDEX.get(raw)
    if cursor is None:
        if has_ticket:
            cursor = 5 if raw in ("completed", "actioned") else 4
        elif has_match:
            cursor = 3
        elif has_intel or enrich_skipped:
            cursor = 2
        else:
            cursor = 0
        if failed and cursor == 5:
            cursor = 4

    if waiting_intel:
        cursor = min(cursor, 2)

    done: list[str] = []
    if cursor >= 1:
        done.append("ingest")
    if cursor >= 2:
        done.append("extract")
    enrich_ok = (has_intel or enrich_skipped) and not waiting_intel
    if cursor >= 3 and enrich_ok:
        done.append("enrich")
    if has_match and cursor >= 3:
        done.append("match")
    if has_ticket:
        if "match" not in done and has_match:
            done.append("match")
        done.append("act")

    if cursor >= 5 and not failed:
        if has_match or has_ticket:
            current = None
            column = "act"
        else:
            current = "match"
            column = "match"
    elif waiting_intel:
        current = "enrich"
        column = "enrich"
    elif cursor >= 4:
        current = "act"
        column = "act"
    elif cursor >= 3:
        current = "match"
        column = "match"
    elif cursor >= 2:
        current = "enrich"
        column = "enrich"
    elif cursor >= 1:
        current = "extract"
        column = "extract"
    else:
        current = "ingest"
        column = "ingest"

    unmatched = (
        column == "match"
        and not has_match
        and not waiting_intel
        and not failed
        and cursor is not None
        and cursor >= 3
    )
    terminal = (current is None and column == "act") or unmatched or failed
    return {
        "done": done,
        "current": current,
        "column": column,
        "waiting": bool(waiting_intel),
        "failed": failed,
        "unmatched": unmatched,
        "terminal": terminal,
    }


STATION_TITLES = {item["id"]: item["title"] for item in WORKFLOW_STATIONS}


def display_state(progress: dict[str, Any]) -> dict[str, Any]:
    """Operator-facing station and run labels used by every page."""
    column = progress.get("column") or "ingest"
    current = progress.get("current")
    station = current or column
    title = STATION_TITLES.get(station, str(station).title())
    if progress.get("failed"):
        return {
            "station": station,
            "station_label": title,
            "run": "failed",
            "run_label": "Failed",
            "filter_key": "failed",
        }
    if progress.get("waiting"):
        return {
            "station": "enrich",
            "station_label": STATION_TITLES["enrich"],
            "run": "waiting",
            "run_label": "Waiting for intel",
            "filter_key": "waiting",
        }
    if progress.get("unmatched"):
        return {
            "station": "match",
            "station_label": STATION_TITLES["match"],
            "run": "unmatched",
            "run_label": "Unmatched",
            "filter_key": "unmatched",
        }
    if current is None:
        done = progress.get("done") or []
        if not done and column in (None, "ingest"):
            return {
                "station": "ingest",
                "station_label": STATION_TITLES["ingest"],
                "run": "live",
                "run_label": "In flight",
                "filter_key": "ingest",
            }
        return {
            "station": "act",
            "station_label": STATION_TITLES["act"],
            "run": "completed",
            "run_label": "Completed",
            "filter_key": "completed",
        }
    return {
        "station": current,
        "station_label": STATION_TITLES.get(current, str(current).title()),
        "run": "live",
        "run_label": "In flight",
        "filter_key": current,
    }


def workflow_flags(progress: dict[str, Any]) -> dict[str, Any]:
    state = display_state(progress)
    return {
        **state,
        "unmatched": bool(progress.get("unmatched")),
        "waiting": bool(progress.get("waiting")),
        "failed": bool(progress.get("failed")),
        "completed": state["run"] == "completed",
        "matched": "match" in (progress.get("done") or []),
    }


def station_journey(progress: dict[str, Any]) -> list[dict[str, Any]]:
    """Five Live Workflow stations for Tracker and CVE detail."""
    done = set(progress.get("done") or [])
    current = progress.get("current")
    rows: list[dict[str, Any]] = []
    for item in WORKFLOW_STATIONS:
        sid = item["id"]
        if progress.get("failed") and current == sid:
            status, detail = "failed", "Failed"
        elif progress.get("waiting") and sid == "enrich":
            status, detail = "waiting", progress.get("wait_reason") or "Waiting for intel"
        elif progress.get("unmatched") and sid == "match":
            status, detail = "miss", "Unmatched"
        elif sid in done:
            status, detail = "done", "Passed"
        elif current == sid:
            status, detail = "live", "In flight"
        else:
            status, detail = "pending", "Not reached"
        rows.append({"id": sid, "title": item["title"], "status": status, "detail": detail})
    return rows


def _clip(text: str | None, limit: int = 700) -> str:
    value = " ".join(str(text or "").split())
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


_SOURCE_KIND = {
    "inline": "Inline CVE",
    "local": "Local folder",
    "smb": "SMB share",
    "outlook": "Outlook / Exchange",
    "email": "Outlook / Exchange",
    "web_api": "ATOM feeds",
    "api_feed": "ATOM feeds",
}

_SOURCE_SHORT = {
    "inline": "Inline CVE",
    "local": "Local",
    "smb": "SMB",
    "outlook": "Exchange",
    "email": "Exchange",
    "web_api": "ATOM",
    "api_feed": "ATOM",
}


def _join_origin(*parts: str) -> str:
    return " · ".join(part for part in parts if part)


def _file_basename(raw: object) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    return Path(text.replace("\\", "/")).name or text


def _feed_label(payload: dict[str, Any], feed_url: str) -> str:
    name = str(payload.get("feed_name") or "").strip()
    if name:
        return name
    kind = str(payload.get("feed_type") or "").strip().lower()
    if kind and kind not in {"atom", "api_feed"}:
        return kind.upper()
    host = (urlparse(feed_url).netloc or "").strip()
    lowered = host.lower()
    if "nvd.nist.gov" in lowered or lowered.startswith("nvd."):
        return "NVD"
    if "cisa.gov" in lowered:
        return "CISA"
    if "microsoft.com" in lowered or "msrc" in lowered:
        return "MSRC"
    if "ubuntu.com" in lowered:
        return "Ubuntu"
    if "exploit-db.com" in lowered:
        return "Exploit-DB"
    return host


def ingest_origin(kind: str, payload: dict[str, Any] | None = None, *, feed_url: str = "") -> dict[str, str]:
    """Human origin for Live Workflow: channel + file / share / feed name."""
    payload = payload if isinstance(payload, dict) else {}
    kind = (kind or "").strip().lower()
    if str(payload.get("origin") or "").strip().lower() == "inline":
        kind = "inline"
    filename = _file_basename(
        payload.get("filename") or payload.get("file_path") or payload.get("_origin_filename") or ""
    )
    location = str(payload.get("location") or "").strip()
    if not location:
        server = str(payload.get("smb_server") or "").strip()
        share = str(payload.get("smb_share") or "").strip()
        location = "\\".join(part for part in (server, share) if part)
    feed = str(payload.get("feed_url") or feed_url or "").strip()
    feed_name = _feed_label(payload, feed)
    subject = str(payload.get("subject") or "").strip()
    folder = str(payload.get("folder") or "").strip()
    short = _SOURCE_SHORT.get(kind, "")
    if kind == "inline":
        headline, detail = "Inline CVE", ""
    elif kind == "local":
        headline, detail = _join_origin("Local", filename), filename
    elif kind == "smb":
        headline = _join_origin("SMB", location, filename)
        detail = _join_origin(location, filename)
    elif kind in {"web_api", "api_feed"}:
        headline, detail = _join_origin("ATOM", feed_name), feed_name
    elif kind in {"outlook", "email"}:
        headline = _join_origin("Exchange", folder, subject)
        detail = _join_origin(folder, subject)
    else:
        headline = short or filename or feed_name or location or subject
        detail = filename or feed_name or location or subject
        if headline == detail:
            detail = ""
    if not headline:
        headline = short or "New ingest"
    return {
        "type": kind,
        "kind": _SOURCE_KIND.get(kind, short),
        "kind_short": short,
        "filename": filename,
        "location": location,
        "feed": feed,
        "feed_name": feed_name,
        "subject": subject,
        "folder": folder,
        "headline": headline,
        "detail": detail,
    }


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _is_refresh_of(vuln: Vulnerability, event: IngestEvent) -> bool:
    created = _as_utc(getattr(vuln, "created_at", None))
    received = _as_utc(getattr(event, "received_at", None))
    if created is None or received is None:
        return False
    return (received - created).total_seconds() > 5


def _event_cve_ids(event: IngestEvent) -> set[str]:
    from app.services.ingestion import _payload_cves

    found: set[str] = set()
    raw = getattr(event, "extracted_cves", None)
    items = raw if isinstance(raw, list) else [raw] if raw else []
    payload = event.payload if isinstance(getattr(event, "payload", None), dict) else {}
    for item in list(items) + _payload_cves(payload):
        cve = str(item or "").upper().replace("–", "-").replace("—", "-")
        if cve.startswith("CVE-"):
            found.add(cve)
    return found


def _ingest_events_by_vuln(db: Session, rows: list[Vulnerability]) -> dict[int, IngestEvent]:
    by_id: dict[int, IngestEvent] = {}
    ids = [row.id for row in rows if getattr(row, "id", None) is not None]
    if ids:
        for run in (
            db.query(PipelineRun)
            .options(joinedload(PipelineRun.event).joinedload(IngestEvent.source))
            .filter(PipelineRun.vulnerability_id.in_(ids), PipelineRun.event_id.isnot(None))
            .order_by(PipelineRun.id.desc())
            .all()
        ):
            if run.vulnerability_id not in by_id and run.event is not None:
                by_id[run.vulnerability_id] = run.event
    missing = [row for row in rows if row.id not in by_id]
    if not missing:
        return by_id
    wanted = {(row.cve_id or "").upper(): row.id for row in missing if row.cve_id}
    if not wanted:
        return by_id
    for event in (
        db.query(IngestEvent)
        .options(joinedload(IngestEvent.source))
        .order_by(IngestEvent.id.desc())
        .limit(800)
        .all()
    ):
        for cve in _event_cve_ids(event):
            vuln_id = wanted.get(cve)
            if vuln_id and vuln_id not in by_id:
                by_id[vuln_id] = event
        if len(by_id) >= len(rows):
            break
    return by_id


def _origin_from_event(event: IngestEvent | None, *, feed_url: str = "", name: str = "") -> dict[str, str]:
    source = event.source if event is not None else None
    kind = ((source.source_type if source else "") or "").strip().lower()
    payload = event.payload if event is not None and isinstance(event.payload, dict) else {}
    origin = ingest_origin(kind, payload, feed_url=feed_url)
    label = ((source.name if source else "") or "").strip() or name
    origin["name"] = label
    return origin


def _source_payload(
    vuln: Vulnerability,
    sources_by_name: dict[str, InputSource],
    event: IngestEvent | None = None,
) -> dict[str, str]:
    name = (getattr(vuln, "source_name", None) or "").strip()
    source = event.source if event is not None else None
    if source is None:
        source = sources_by_name.get(name.lower())
    blob = getattr(vuln, "enrichment", None) or {}
    feed_url = ""
    if isinstance(blob, dict):
        feed_url = str(blob.get("feed_link") or blob.get("feed_url") or "").strip()
    if event is not None:
        return _origin_from_event(event, feed_url=feed_url, name=name)
    kind = ((source.source_type if source else "") or "").strip().lower()
    origin = ingest_origin(kind, {}, feed_url=feed_url)
    if source and (source.name or "").strip():
        name = (source.name or "").strip()
    origin["name"] = name
    return origin


_DUPLICATE_PROGRESS = {
    "done": ["ingest"],
    "current": "extract",
    "column": "extract",
    "waiting": False,
    "failed": False,
    "unmatched": False,
    "terminal": True,
}


def _empty_intel() -> dict[str, Any]:
    return {
        "severity": "UNKNOWN",
        "priority": "",
        "cvss_score": None,
        "cvss_vector": "",
        "epss_score": None,
        "epss_percentile": None,
        "attack_vector": "",
        "attack_complexity": "",
        "privileges_required": "",
        "user_interaction": "",
        "cwe_ids": [],
        "ai_used": False,
        "waiting": False,
        "skipped": False,
    }


def _vuln_workflow_row(
    vuln: Vulnerability,
    *,
    source: dict[str, str],
    match_rows: list[dict[str, Any]],
    ticket_rows: list[dict[str, Any]],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    progress = progress_for_vuln(vuln, has_match=bool(match_rows), has_ticket=bool(ticket_rows))
    row = {
        "cve_id": vuln.cve_id,
        "title": _story_name(vuln),
        "description": _clip(vuln.description),
        "vendor": vuln.vendor or "",
        "product": vuln.product or "",
        "product_type": vuln.product_type or "",
        "version": vuln.affected_versions or "",
        "severity": vuln.severity or "UNKNOWN",
        "intel": _intel_details(vuln),
        "matches": match_rows,
        "tickets": ticket_rows,
        "source": source,
        "pipeline_status": canonical_pipeline_status(vuln),
        "created_at": _iso(getattr(vuln, "created_at", None)),
        "updated_at": _iso(getattr(vuln, "updated_at", None)),
        "duplicate": False,
        "refreshed": False,
        **progress,
    }
    if extra:
        row.update(extra)
    return row


def _duplicate_play_row(cve_id: str, event: IngestEvent) -> dict[str, Any]:
    stamp = _iso(getattr(event, "received_at", None))
    return {
        "play_key": f"dup-{event.id}-{cve_id}",
        "cve_id": cve_id,
        "duplicate": True,
        "refreshed": False,
        "title": "",
        "description": "",
        "vendor": "",
        "product": "",
        "product_type": "",
        "version": "",
        "severity": "UNKNOWN",
        "intel": _empty_intel(),
        "matches": [],
        "tickets": [],
        "source": _origin_from_event(event),
        "pipeline_status": "duplicate",
        "created_at": stamp,
        "updated_at": stamp,
        **_DUPLICATE_PROGRESS,
    }


def _matches_tickets_for(
    db: Session,
    vuln_id: int,
    matches_by_id: dict[int, list[AssetMatch]],
    tickets_by_id: dict[int, list[JiraTicket]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if vuln_id not in matches_by_id:
        matches_by_id[vuln_id] = (
            db.query(AssetMatch)
            .options(joinedload(AssetMatch.asset))
            .filter(AssetMatch.vulnerability_id == vuln_id)
            .all()
        )
    if vuln_id not in tickets_by_id:
        tickets_by_id[vuln_id] = (
            db.query(JiraTicket).filter(JiraTicket.vulnerability_id == vuln_id).all()
        )
    return _match_payloads(matches_by_id[vuln_id]), _ticket_payloads(tickets_by_id[vuln_id])


def _payload_is_atom(payload: dict[str, Any]) -> bool:
    return bool(payload.get("_refresh") or payload.get("feed_url") or payload.get("entry_id"))


def _recent_workflow_plays(
    db: Session,
    sources_by_name: dict[str, InputSource],
    classified_by_id: dict[int, dict[str, Any]],
    *,
    limit: int = 20,
) -> list[dict[str, Any]]:
    from app.services.ingestion import _event_is_duplicate

    events = (
        db.query(IngestEvent)
        .options(joinedload(IngestEvent.source))
        .order_by(IngestEvent.id.desc())
        .limit(80)
        .all()
    )
    plays: list[dict[str, Any]] = []
    vulns_by_cve: dict[str, Vulnerability | None] = {}
    matches_by_id: dict[int, list[AssetMatch]] = {}
    tickets_by_id: dict[int, list[JiraTicket]] = {}

    def vuln_for(cve_id: str) -> Vulnerability | None:
        key = (cve_id or "").upper()
        if key not in vulns_by_cve:
            vulns_by_cve[key] = db.query(Vulnerability).filter(Vulnerability.cve_id == key).first()
        return vulns_by_cve[key]

    for event in events:
        payload = event.payload if isinstance(getattr(event, "payload", None), dict) else {}
        cves = [cve for cve in _event_cve_ids(event)]
        if not cves:
            continue
        if _event_is_duplicate(event):
            for cve in cves[:3]:
                plays.append(_duplicate_play_row(cve, event))
            if len(plays) >= limit:
                break
            continue
        is_rerun = bool(payload.get("_rerun"))
        if not is_rerun and not _payload_is_atom(payload):
            continue
        for cve in cves[:1]:
            vuln = vuln_for(cve)
            if vuln is None:
                continue
            if not is_rerun and not _is_refresh_of(vuln, event):
                continue
            cached = classified_by_id.get(vuln.id)
            if cached is not None:
                match_rows, ticket_rows = cached["matches"], cached["tickets"]
            else:
                match_rows, ticket_rows = _matches_tickets_for(
                    db, vuln.id, matches_by_id, tickets_by_id
                )
            origin = _source_payload(vuln, sources_by_name, event)
            feed = origin.get("feed_name") or "ATOM"
            stamp = _iso(getattr(event, "received_at", None))
            plays.append(
                _vuln_workflow_row(
                    vuln,
                    source=origin,
                    match_rows=match_rows,
                    ticket_rows=ticket_rows,
                    extra={
                        "play_key": f"ref-{event.id}",
                        "refreshed": True,
                        "refresh_label": "Re-run" if is_rerun else f"Updated from {feed}",
                        "created_at": stamp,
                        "updated_at": stamp,
                    },
                )
            )
        if len(plays) >= limit:
            break
    return plays[:limit]


def _story_name(vuln: Vulnerability) -> str:
    title = (vuln.title or "").strip()
    cve = (vuln.cve_id or "").strip()
    if not title or title.upper() == cve.upper():
        return ""
    return title


def _intel_details(vuln: Vulnerability) -> dict[str, Any]:
    cwes = vuln.cwe_ids if isinstance(getattr(vuln, "cwe_ids", None), list) else []
    blob = getattr(vuln, "enrichment", None) or {}
    return {
        "severity": (vuln.severity or "").strip() or "UNKNOWN",
        "priority": (vuln.priority or "").strip(),
        "cvss_score": vuln.cvss_score,
        "cvss_vector": vuln.cvss_vector or "",
        "epss_score": vuln.epss_score,
        "epss_percentile": vuln.epss_percentile,
        "attack_vector": vuln.attack_vector or "",
        "attack_complexity": vuln.attack_complexity or "",
        "privileges_required": vuln.privileges_required or "",
        "user_interaction": vuln.user_interaction or "",
        "cwe_ids": [str(item) for item in cwes if item],
        "ai_used": bool(getattr(vuln, "ai_enrichment_used", False)),
        "waiting": _waiting_intel(vuln),
        "wait_reason": str(blob.get("wait_reason") or "") if isinstance(blob, dict) else "",
        "retry_at": str(blob.get("retry_at") or "") if isinstance(blob, dict) else "",
        "wait_kind": str(blob.get("wait_kind") or "") if isinstance(blob, dict) else "",
        "skipped": _enrich_skipped(vuln),
    }


def _match_payloads(matches: list[AssetMatch]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in matches:
        asset = getattr(item, "asset", None)
        if asset is None:
            continue
        rows.append(
            {
                "name": asset.name or "",
                "vendor": asset.vendor or "",
                "product": asset.product or "",
                "version": asset.version or "",
                "system_type": asset.system_type or "",
                "team": asset.team or "",
                "owner_name": asset.owner_name or "",
                "owner_email": asset.owner_email or "",
                "confidence": item.confidence,
            }
        )
    return rows


def _ticket_payloads(tickets: list[JiraTicket]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for ticket in tickets:
        rows.append(
            {
                "key": ticket.ticket_key or "",
                "type": ticket.ticket_type or "",
                "url": ticket.url or "",
                "summary": ticket.summary or "",
                "assignee": ticket.assignee or "",
                "dry_run": bool(ticket.dry_run),
            }
        )
    return rows


def classify_vulnerabilities(
    db: Session, vulns: list[Vulnerability] | None = None
) -> list[dict[str, Any]]:
    """Station flags for every CVE, using the same rules as Live Workflow."""
    if vulns is None:
        vulns = db.query(Vulnerability).order_by(Vulnerability.updated_at.desc()).all()
    ids = [row.id for row in vulns if getattr(row, "id", None) is not None]
    matches_by_id: dict[int, list[AssetMatch]] = {}
    tickets_by_id: dict[int, list[JiraTicket]] = {}
    if ids:
        for item in (
            db.query(AssetMatch)
            .options(joinedload(AssetMatch.asset))
            .filter(AssetMatch.vulnerability_id.in_(ids))
            .all()
        ):
            matches_by_id.setdefault(item.vulnerability_id, []).append(item)
        for ticket in db.query(JiraTicket).filter(JiraTicket.vulnerability_id.in_(ids)).all():
            tickets_by_id.setdefault(ticket.vulnerability_id, []).append(ticket)
    classified: list[dict[str, Any]] = []
    for vuln in vulns:
        match_rows = _match_payloads(matches_by_id.get(vuln.id, []))
        ticket_rows = _ticket_payloads(tickets_by_id.get(vuln.id, []))
        classified.append(
            {
                "vuln": vuln,
                "progress": progress_for_vuln(
                    vuln, has_match=bool(match_rows), has_ticket=bool(ticket_rows)
                ),
                "matches": match_rows,
                "tickets": ticket_rows,
            }
        )
    return classified


def count_workflow_states(classified: list[dict[str, Any]]) -> dict[str, Any]:
    """KPI cubes shared by Live Workflow, Main, and stage pages."""
    unmatched = waiting = completed = inflight = failed = 0
    matched = enriched = extracted = 0
    matching_live = acting_live = actioned = 0
    ai_extract = ai_enrich = ai_match = incomplete = 0
    tickets = 0
    stations = {item["id"]: {"live": 0, "done": 0} for item in WORKFLOW_STATIONS}
    for item in classified:
        vuln: Vulnerability = item["vuln"]
        progress = item["progress"]
        tickets += len(item.get("tickets") or [])
        if progress.get("failed"):
            failed += 1
        if progress.get("waiting"):
            waiting += 1
        if progress.get("unmatched"):
            unmatched += 1
        if progress.get("current") is None:
            completed += 1
        if progress.get("current") and not progress.get("terminal") and not progress.get("failed"):
            inflight += 1
            current = progress["current"]
            if current in stations:
                stations[current]["live"] += 1
        for station in progress.get("done") or []:
            if station in stations:
                stations[station]["done"] += 1
        done = progress.get("done") or []
        if "extract" in done:
            extracted += 1
        if "enrich" in done:
            enriched += 1
        if "match" in done:
            matched += 1
        if progress.get("current") == "match" and not progress.get("unmatched"):
            matching_live += 1
        if progress.get("current") == "act" and not progress.get("failed"):
            acting_live += 1
        if "act" in done and progress.get("current") is None:
            actioned += 1
        if getattr(vuln, "ai_extraction_used", False):
            ai_extract += 1
        if getattr(vuln, "ai_enrichment_used", False):
            ai_enrich += 1
        if getattr(vuln, "ai_matching_used", False):
            ai_match += 1
        if reached_enrichment(progress) and not progress.get("waiting"):
            blob = getattr(vuln, "enrichment", None) or {}
            skipped = isinstance(blob, dict) and bool(blob.get("skipped"))
            if not skipped and (not vuln.vendor or not vuln.product or vuln.cvss_score is None):
                incomplete += 1
    return {
        "inflight": inflight,
        "waiting": waiting,
        "unmatched": unmatched,
        "completed": completed,
        "failed": failed,
        "extracted": extracted,
        "enriched": enriched,
        "matched": matched,
        "matching_live": matching_live,
        "acting_live": acting_live,
        "actioned": actioned,
        "ai_extract": ai_extract,
        "ai_enrich": ai_enrich,
        "ai_match": ai_match,
        "incomplete": incomplete,
        "tickets": tickets,
        "cves": len(classified),
        "stations": stations,
    }


def build_workflow_snapshot(db: Session, limit: int = 80) -> dict[str, Any]:
    all_rows = db.query(Vulnerability).order_by(Vulnerability.updated_at.desc()).all()
    classified = classify_vulnerabilities(db, all_rows)
    totals = count_workflow_states(classified)
    rows = all_rows[:limit]
    sources_by_name = {
        (source.name or "").strip().lower(): source
        for source in db.query(InputSource).all()
        if (source.name or "").strip()
    }
    events_by_id = _ingest_events_by_vuln(db, rows)
    catalog = []
    by_id = {item["vuln"].id: item for item in classified}
    for vuln in rows:
        item = by_id.get(vuln.id)
        match_rows = item["matches"] if item else []
        ticket_rows = item["tickets"] if item else []
        catalog.append(
            _vuln_workflow_row(
                vuln,
                source=_source_payload(vuln, sources_by_name, events_by_id.get(vuln.id)),
                match_rows=match_rows,
                ticket_rows=ticket_rows,
            )
        )
    in_flight = [row for row in catalog if row["current"] and not row["terminal"] and not row.get("failed")]
    settled = [row for row in catalog if not (row["current"] and not row["terminal"] and not row.get("failed"))]
    in_flight.sort(key=lambda row: row.get("updated_at") or "", reverse=True)
    settled.sort(key=lambda row: row.get("updated_at") or "", reverse=True)
    catalog = in_flight + settled
    plays = _recent_workflow_plays(db, sources_by_name, by_id)
    refresh_ids = {
        (row.get("cve_id") or "").upper()
        for row in plays
        if row.get("refreshed") and not row.get("duplicate")
    }
    if refresh_ids:
        catalog = [row for row in catalog if (row.get("cve_id") or "").upper() not in refresh_ids]
    cves = plays + catalog
    stations = [
        {
            **item,
            "live": totals["stations"][item["id"]]["live"],
            "passed": totals["stations"][item["id"]]["done"],
        }
        for item in WORKFLOW_STATIONS
    ]
    return {
        "stations": stations,
        "cves": cves,
        "summary": {
            "inflight": totals["inflight"],
            "waiting": totals["waiting"],
            "unmatched": totals["unmatched"],
            "completed": totals["completed"],
        },
        "listening": totals["cves"] == 0,
    }
