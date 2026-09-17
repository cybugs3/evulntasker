"""
Step 5 — act: tickets, Sigma/SIEM detections, optional Exchange and Gmail notify.
"""

from __future__ import annotations

import hashlib
import logging

from sqlalchemy.orm import Session

from app.config import get_settings
from app.integrations.exchange import ExchangeClient
from app.integrations.gmail import gmail_configured, send_gmail_ticket
from app.integrations.ticketing import get_ticketing_clients
from app.integrations.siem import generate_detections
from app.models.detection import DetectionArtifact
from app.models.enums import PipelineStatus
from app.models.jira import JiraTicket
from app.models.vulnerability import Vulnerability
from app.pipeline.state import begin_step, complete_step, set_status
from app.services.mail_templates import render_hunt, render_owner
from app.utils.textclean import clean_email, email_domain_allowed, parse_email_domains

log = logging.getLogger(__name__)


def _clean_email(value: str | None) -> str:
    return clean_email(value)


def _act_email_domains(settings) -> list[str]:
    return parse_email_domains(getattr(settings, "ticketing_email_domains", "") or "")


def _allow_act_email(email: str, domains: list[str], cve_id: str, role: str) -> bool:
    if email_domain_allowed(email, domains):
        return True
    log.warning("%s skipped %s mail to %s — domain is not in the allow-list", cve_id, role, email)
    return False


def _mail_ticket_key(kind: str, email: str) -> str:
    prefix = "MAIL-h-" if kind == "hunt" else "MAIL-o-"
    local = (email.split("@")[0] if email else kind)
    local = "".join(ch for ch in local if ch.isalnum() or ch in "._-")[:12]
    digest = hashlib.sha1((email or "").strip().lower().encode()).hexdigest()[:6]
    return f"{prefix}{local or kind}-{digest}"[:32]


def _owner_payload(vuln: Vulnerability) -> dict:
    match = vuln.matches[0] if vuln.matches else None
    asset = match.asset if match else None
    inferred = {}
    if isinstance(vuln.enrichment, dict):
        inferred = vuln.enrichment.get("inferred_owner") or {}
    return {
        "cve_id": vuln.cve_id,
        "severity": vuln.severity,
        "priority": vuln.priority,
        "cvss_score": vuln.cvss_score,
        "epss_score": vuln.epss_score,
        "attack_vector": vuln.attack_vector,
        "system_type": (asset.system_type if asset else vuln.product_type) or "unknown",
        "version": (asset.version if asset else vuln.affected_versions) or "unknown",
        "vendor": vuln.vendor,
        "product": vuln.product,
        "asset_owner": (asset.owner_name if asset else None) or inferred.get("owner_name") or "Unassigned",
        "username": (asset.owner_username if asset else None) or inferred.get("owner_username") or "security-ops",
        "email": (asset.owner_email if asset else None) or inferred.get("owner_email") or "soc@example.com",
        "team": (asset.team if asset else None) or inferred.get("team") or "Security Operations",
        "asset_name": asset.name if asset else "unmatched",
    }


def _matched_owner_groups(vuln: Vulnerability, fallback_email: str = "") -> list[dict]:
    """One group per Internal-systems owner. Same owner with several systems gets one mail."""
    groups: dict[str, dict] = {}
    fallback = _clean_email(fallback_email)
    for match in vuln.matches or []:
        asset = match.asset
        if asset is None or asset.active is False:
            continue
        email = _clean_email(asset.owner_email) or fallback
        if not email:
            log.info(
                "%s skipped email for %s — Internal systems row has no owner_email",
                vuln.cve_id,
                asset.name or f"asset:{asset.id}",
            )
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


def _payload_for_owner_group(vuln: Vulnerability, group: dict) -> dict:
    assets = group.get("assets") or []
    first = assets[0] if assets else None
    names = []
    for asset in assets:
        label = " / ".join(part for part in (asset.vendor, asset.product, asset.version) if part)
        names.append(f"{asset.name or label or 'system'} ({label})" if label else (asset.name or "system"))
    return {
        "cve_id": vuln.cve_id,
        "severity": vuln.severity,
        "priority": vuln.priority,
        "cvss_score": vuln.cvss_score,
        "epss_score": vuln.epss_score,
        "attack_vector": vuln.attack_vector,
        "system_type": (first.system_type if first else vuln.product_type) or "unknown",
        "version": (first.version if first else vuln.affected_versions) or "unknown",
        "vendor": vuln.vendor,
        "product": vuln.product,
        "asset_owner": group["asset_owner"],
        "username": group["username"],
        "email": group["email"],
        "team": group["team"],
        "asset_name": "; ".join(names) or "unmatched",
    }


def _owner_description(vuln: Vulnerability, payload: dict) -> str:
    _subject, body = render_owner(vuln, payload)
    return body


def _hunt_description(vuln: Vulnerability, detections: dict[str, str]) -> str:
    _subject, body = render_hunt(vuln, detections)
    return body


def _store_detections(db: Session, vuln: Vulnerability, detections: dict[str, str]) -> None:
    if vuln.detections:
        return
    db.add(
        DetectionArtifact(
            vulnerability_id=vuln.id,
            sigma_rule=detections.get("sigma_rule") or "",
            kql=detections.get("kql") or "",
            xql=detections.get("xql") or "",
            aqk=detections.get("aqk") or "",
            ekql=detections.get("ekql") or "",
        )
    )


def _record_ticket(db: Session, vuln: Vulnerability, store: bool, **kwargs) -> None:
    if not store or vuln.id is None:
        return
    db.add(JiraTicket(vulnerability_id=vuln.id, **kwargs))


async def _open_email_owner_tasks(
    db: Session,
    vuln: Vulnerability,
    ticketing,
    owner_project: str,
    existing_assignees: set[str],
    fallback_email: str = "",
    *,
    store: bool = True,
    domains: list[str] | None = None,
) -> tuple[dict | None, list[dict]]:
    groups = _matched_owner_groups(vuln, fallback_email=fallback_email)
    last = None
    issues: list[dict] = []
    if not groups:
        log.info("%s email ticketing — no Internal systems owner_email to notify", vuln.cve_id)
        return None, issues
    errors: list[str] = []
    allowed = domains if domains is not None else _act_email_domains(get_settings())
    for group in groups:
        email = group["email"]
        if email.lower() in existing_assignees:
            continue
        if not _allow_act_email(email, allowed, vuln.cve_id, "owner"):
            continue
        payload = _payload_for_owner_group(vuln, group)
        subject, description = render_owner(vuln, payload)
        try:
            last = await ticketing.create_issue(
                project_key=owner_project,
                summary=subject or f"[{payload['priority']}] {vuln.cve_id} — {payload['product'] or 'unknown product'}",
                description=description or _owner_description(vuln, payload),
                assignee=email,
                labels=["evulntasker", "owner-action", (vuln.severity or "unknown").lower()],
                priority=payload["priority"],
                to=email,
            )
        except Exception as exc:
            log.exception("%s SMTP/owner mail failed for %s", vuln.cve_id, email)
            errors.append(f"{email}: {exc}")
            continue
        key = last.get("key") or _mail_ticket_key("owner", email)
        issues.append(
            {
                "provider": "email",
                "type": "owner",
                "key": key,
                "url": last.get("url"),
                "dry_run": last.get("dry_run"),
                "assignee": email,
            }
        )
        _record_ticket(
            db,
            vuln,
            store,
            ticket_key=key[:32],
            ticket_type="owner",
            url=last["url"],
            assignee=email[:128],
            summary=f"{vuln.cve_id} owner action · {email}",
            dry_run=last["dry_run"],
            raw_response=_pack_ticket_raw("email", last.get("raw")),
        )
        existing_assignees.add(email.lower())
    if errors and not issues:
        raise RuntimeError("; ".join(errors))
    if errors:
        log.warning("%s mailed some owners; skipped: %s", vuln.cve_id, "; ".join(errors))
    return last, issues


def _projects_for(settings, provider: str) -> tuple[str, str]:
    if provider == "custom":
        return settings.custom_owner_project, settings.custom_hunt_project
    if provider == "monday":
        board = settings.monday_board_id or "BOARD"
        return board, board
    if provider == "email":
        return "MAIL", "MAIL"
    return settings.jira_project_key, settings.jira_hunt_project_key


def _ticket_channel(ticket) -> str:
    raw = ticket.raw_response or ""
    key = ticket.ticket_key or ""
    if '"provider": "email"' in raw or key.startswith("MAIL-"):
        return "email"
    if '"provider": "monday"' in raw or key.startswith("MON-"):
        return "monday"
    if '"provider": "custom"' in raw:
        return "custom"
    return "jira"


def _pack_ticket_raw(provider: str, raw: dict | None) -> str:
    return str({"provider": provider, "raw": raw or {}})


async def take_action(
    db: Session,
    vuln: Vulnerability,
    *,
    audit: bool = True,
    store: bool = True,
) -> dict:
    """Open tickets according to Settings.

    ``audit=False`` skips AuditLog / pipeline-run documentation and does not commit.
    ``store=False`` still talks to ticketing providers but does not write ticket/detection rows.
    """
    if audit:
        begin_step(db, vuln, PipelineStatus.ACTIONED, f"Action started for {vuln.cve_id}")
    settings = get_settings()
    payload = _owner_payload(vuln)
    detections = generate_detections(vuln)
    if store:
        _store_detections(db, vuln, detections)

    clients = get_ticketing_clients(settings)
    owner_issue = hunt_issue = None
    issues: list[dict] = []
    hunt_to = _clean_email(settings.ticketing_hunt_email)
    domains = _act_email_domains(settings)
    if hunt_to and not _allow_act_email(hunt_to, domains, vuln.cve_id, "hunt"):
        hunt_to = ""

    for provider, ticketing in clients:
        owner_project, hunt_project = _projects_for(settings, provider)
        has_owner = any(
            ticket.ticket_type == "owner" and _ticket_channel(ticket) == provider
            for ticket in vuln.tickets
        )
        has_hunt = any(
            ticket.ticket_type in {"threat_hunt", "hunt"} and _ticket_channel(ticket) == provider
            for ticket in vuln.tickets
        )

        if provider == "email":
            owner_issue, email_issues = await _open_email_owner_tasks(
                db,
                vuln,
                ticketing,
                owner_project,
                existing_assignees={
                    (ticket.assignee or "").strip().lower()
                    for ticket in vuln.tickets
                    if ticket.ticket_type == "owner" and _ticket_channel(ticket) == "email"
                },
                fallback_email=settings.ticketing_fallback_owner_email,
                store=store,
                domains=domains,
            )
            issues.extend(email_issues)
        elif not has_owner:
            payload = _owner_payload(vuln)
            owner_subject, owner_body = render_owner(vuln, payload)
            owner_issue = await ticketing.create_issue(
                project_key=owner_project,
                summary=owner_subject or f"[{payload['priority']}] {vuln.cve_id} — {payload['product'] or 'unknown product'}",
                description=owner_body or _owner_description(vuln, payload),
                assignee=payload["username"],
                labels=["evulntasker", "owner-action", (vuln.severity or "unknown").lower()],
                priority=payload["priority"],
            )
            issues.append(
                {
                    "provider": provider,
                    "type": "owner",
                    "key": owner_issue.get("key"),
                    "url": owner_issue.get("url"),
                    "dry_run": owner_issue.get("dry_run"),
                    "assignee": payload["username"],
                }
            )
            _record_ticket(
                db,
                vuln,
                store,
                ticket_key=owner_issue["key"],
                ticket_type="owner",
                url=owner_issue["url"],
                assignee=payload["username"],
                summary=f"{vuln.cve_id} owner action",
                dry_run=owner_issue["dry_run"],
                raw_response=_pack_ticket_raw(provider, owner_issue.get("raw")),
            )

        skip_email_hunt = provider == "email" and not hunt_to
        if not has_hunt and not skip_email_hunt:
            hunt_subject, hunt_body = render_hunt(vuln, detections)
            try:
                hunt_issue = await ticketing.create_issue(
                    project_key=hunt_project,
                    summary=hunt_subject or f"[HUNT] {vuln.cve_id} — Sigma/SIEM detections",
                    description=hunt_body or _hunt_description(vuln, detections),
                    labels=["evulntasker", "threat-hunting", (vuln.severity or "unknown").lower()],
                    priority=payload["priority"],
                    **({"to": hunt_to} if provider == "email" else {}),
                )
            except Exception:
                log.exception("%s hunt mail failed for %s", vuln.cve_id, hunt_to or provider)
                if not issues:
                    raise
                continue
            hunt_key = _mail_ticket_key("hunt", hunt_to) if provider == "email" else hunt_issue["key"]
            issues.append(
                {
                    "provider": provider,
                    "type": "threat_hunt",
                    "key": hunt_key,
                    "url": hunt_issue.get("url"),
                    "dry_run": hunt_issue.get("dry_run"),
                    "assignee": hunt_to or "threat-hunting",
                }
            )
            _record_ticket(
                db,
                vuln,
                store,
                ticket_key=hunt_key,
                ticket_type="threat_hunt",
                url=hunt_issue["url"],
                assignee=(hunt_to[:128] if hunt_to else "threat-hunting"),
                summary=f"{vuln.cve_id} threat hunting",
                dry_run=hunt_issue["dry_run"],
                raw_response=_pack_ticket_raw(provider, hunt_issue.get("raw")),
            )

    owner_key = (owner_issue or {}).get("key") if owner_issue else "existing"
    hunt_key = (hunt_issue or {}).get("key") if hunt_issue else "existing"
    body = (
        f"EVulnTasker processed {vuln.cve_id}.\n"
        f"Owner ticket: {owner_key}\n"
        f"Hunting ticket: {hunt_key}\n\n"
        f"{_owner_description(vuln, payload)}"
    )
    if any(name != "email" for name, _client in clients):
        try:
            ExchangeClient().send(
                to=list({payload["email"], "threat-hunting@example.com"}),
                subject=f"[EVulnTasker] {vuln.cve_id} {payload['severity']} assigned to {payload['team']}",
                body=body,
            )
        except Exception:
            log.exception("Failed to send Exchange notification for %s", vuln.cve_id)

    if gmail_configured(settings):
        try:
            await send_gmail_ticket(vuln, detections=detections, settings=settings)
        except Exception:
            log.exception("Failed to send Gmail ticket for %s", vuln.cve_id)

    opened = [name for name, _client in clients]
    message = (
        f"Opened owner/hunt tickets via {', '.join(opened)} and generated detections for {vuln.cve_id}"
        if opened
        else f"No ticketing provider enabled — detections generated for {vuln.cve_id}"
    )
    details = {"owner_ticket": owner_key, "hunt_ticket": hunt_key, "providers": opened}
    if audit:
        complete_step(db, vuln, PipelineStatus.ACTIONED, message, details)
    elif store:
        set_status(db, vuln, PipelineStatus.ACTIONED)
    return {**details, "issues": issues, "message": message}

