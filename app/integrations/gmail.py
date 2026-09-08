"""Gmail SMTP delivery for Act-step vulnerability tickets.

Connects to smtp.gmail.com:587 with STARTTLS. Send failures are logged and
never raised to the pipeline caller.
"""

from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path
from typing import Any

import structlog
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.config import Settings, get_settings
from app.models.vulnerability import Vulnerability

log = structlog.stdlib.get_logger(__name__)

GMAIL_SMTP_HOST = "smtp.gmail.com"
GMAIL_SMTP_PORT = 587

_TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "web" / "templates" / "email"
_jinja = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)


def gmail_configured(settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    sender = str(getattr(settings, "gmail_sender_email", "") or "").strip()
    password = str(getattr(settings, "gmail_app_password", "") or "").strip()
    receiver = str(getattr(settings, "gmail_receiver_email", "") or "").strip()
    return bool(sender and password and receiver)


def _app_password(value: str) -> str:
    return "".join((value or "").split())


def format_epss_probability(score: Any) -> str:
    if score is None or score == "":
        return "n/a"
    try:
        number = float(score)
    except (TypeError, ValueError):
        return str(score)
    if 0 <= number <= 1:
        return f"{number * 100:.2f}%"
    return f"{number:.2f}"


def _matched_assets(vuln: Vulnerability) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for match in vuln.matches or []:
        asset = getattr(match, "asset", None)
        if asset is None:
            continue
        rows.append(
            {
                "name": getattr(asset, "name", None) or "unnamed",
                "vendor": getattr(asset, "vendor", None) or "",
                "product": getattr(asset, "product", None) or "",
                "version": getattr(asset, "version", None) or "",
                "owner": getattr(asset, "owner_name", None) or "",
                "email": getattr(asset, "owner_email", None) or "",
                "team": getattr(asset, "team", None) or "",
            }
        )
    return rows


def _remediation(vuln: Vulnerability) -> str:
    product = " ".join(part for part in (vuln.vendor, vuln.product) if part) or "the affected product"
    versions = vuln.affected_versions or "the installed version"
    return (
        f"Apply the vendor security update for {product} ({versions}). "
        "Confirm the patch on each matched asset, then hunt with the Sigma/SIEM rules below. "
        f"Reference: https://nvd.nist.gov/vuln/detail/{vuln.cve_id}"
    )


def _summary(vuln: Vulnerability) -> str:
    title = (vuln.title or "").strip()
    if title:
        return title
    description = (vuln.description or "").strip()
    if description:
        return description.splitlines()[0][:500]
    return "No summary provided"


def render_gmail_ticket_html(
    vuln: Vulnerability,
    detections: dict[str, str] | None = None,
) -> str:
    detections = detections or {}
    assets = _matched_assets(vuln)
    template = _jinja.get_template("gmail_ticket.html")
    return template.render(
        cve_id=vuln.cve_id,
        summary=_summary(vuln),
        description=(vuln.description or "").strip(),
        severity=vuln.severity or "UNKNOWN",
        cvss_score=vuln.cvss_score if vuln.cvss_score is not None else "n/a",
        epss_probability=format_epss_probability(vuln.epss_score),
        vendor=vuln.vendor or "unknown",
        product=vuln.product or "unknown",
        affected_versions=vuln.affected_versions or "unknown",
        assets=assets,
        unmatched=not assets,
        remediation=_remediation(vuln),
        sigma_rule=(detections.get("sigma_rule") or "").strip(),
        kql=(detections.get("kql") or "").strip(),
        xql=(detections.get("xql") or "").strip(),
        aqk=(detections.get("aqk") or "").strip(),
        ekql=(detections.get("ekql") or "").strip(),
    )


def _plain_text(
    vuln: Vulnerability,
    detections: dict[str, str] | None = None,
) -> str:
    detections = detections or {}
    assets = _matched_assets(vuln)
    if assets:
        asset_lines = []
        for asset in assets:
            product = " ".join(part for part in (asset["vendor"], asset["product"], asset["version"]) if part)
            asset_lines.append(f"- {asset['name']}" + (f" ({product})" if product else ""))
        asset_block = "\n".join(asset_lines)
    else:
        asset_block = "No Internal systems row matched this CVE."
    sigma = (detections.get("sigma_rule") or "").strip()
    parts = [
        f"{vuln.cve_id}: {_summary(vuln)}",
        "",
        f"CVSS: {vuln.cvss_score if vuln.cvss_score is not None else 'n/a'} ({vuln.severity or 'UNKNOWN'})",
        f"EPSS: {format_epss_probability(vuln.epss_score)}",
        f"Product: {vuln.vendor or 'unknown'} / {vuln.product or 'unknown'} ({vuln.affected_versions or 'unknown'})",
        "",
        "Matched assets",
        asset_block,
        "",
        "Suggested remediation",
        _remediation(vuln),
    ]
    if sigma:
        parts.extend(["", "Sigma hunting rule", sigma])
    kql = (detections.get("kql") or "").strip()
    if kql:
        parts.extend(["", "Microsoft Sentinel / KQL", kql])
    xql = (detections.get("xql") or "").strip()
    if xql:
        parts.extend(["", "Cortex XQL", xql])
    return "\n".join(parts) + "\n"


async def _aiosmtp_send(*args: Any, **kwargs: Any) -> Any:
    """Import aiosmtplib only when sending so a missing wheel cannot block startup."""
    import aiosmtplib

    return await aiosmtplib.send(*args, **kwargs)


async def send_gmail_ticket(
    vuln: Vulnerability,
    detections: dict[str, str] | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Send an HTML vulnerability ticket to GMAIL_RECEIVER_EMAIL.

    Returns a result dict. Never raises — SMTP errors are logged with structlog.
    """
    settings = settings or get_settings()
    cve_id = getattr(vuln, "cve_id", None)
    if not gmail_configured(settings):
        log.info("gmail_skipped", cve_id=cve_id, reason="not_configured")
        return {"ok": False, "skipped": True, "reason": "not_configured"}

    sender = (settings.gmail_sender_email or "").strip()
    receiver = (settings.gmail_receiver_email or "").strip()
    password = _app_password(settings.gmail_app_password)
    try:
        html_body = render_gmail_ticket_html(vuln, detections)
        message = EmailMessage()
        message["From"] = sender
        message["To"] = receiver
        message["Subject"] = (
            f"[EVulnTasker] {vuln.cve_id} — {(_summary(vuln) or 'vulnerability ticket')[:80]}"
        )
        message.set_content(_plain_text(vuln, detections))
        message.add_alternative(html_body, subtype="html")
        await _aiosmtp_send(
            message,
            hostname=GMAIL_SMTP_HOST,
            port=GMAIL_SMTP_PORT,
            start_tls=True,
            username=sender,
            password=password,
        )
        log.info("gmail_ticket_sent", cve_id=cve_id, to=receiver)
        return {"ok": True, "skipped": False, "to": receiver}
    except Exception as exc:
        log.exception("gmail_send_failed", cve_id=cve_id, error=str(exc))
        return {"ok": False, "skipped": False, "error": str(exc)}
