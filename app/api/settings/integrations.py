"""Enrichment, AI, asset APIs, ticketing, and maintenance settings."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.settings.common import save_env
from app.config import get_settings as get_app_settings
from app.db.session import get_db

router = APIRouter()

AI_PROVIDER_DEFAULTS = {
    "gemini": (
        "https://generativelanguage.googleapis.com/v1beta/openai",
        "gemini-1.5-flash",
    ),
    "chatgpt": ("https://api.openai.com/v1", "gpt-4o-mini"),
    "azure_openai": (
        "https://YOUR-RESOURCE.openai.azure.com/openai/deployments/YOUR-DEPLOYMENT",
        "gpt-4o",
    ),
    "github_copilot": ("https://api.githubcopilot.com", "gpt-4o"),
}


class IntelSourceIn(BaseModel):
    id: int | None = None
    name: str = ""
    feed_type: str = "nvd"
    endpoint: str = ""
    enabled: bool = False
    api_key: str = ""
    notes: str = ""


class IntelSourcesIn(BaseModel):
    intel_start_date: str | None = None
    sources: list[IntelSourceIn] = Field(default_factory=list)


class EnrichmentIn(BaseModel):
    enrichment_enabled: bool | None = None
    nvd_enabled: bool | None = None
    nvd_api_base: str | None = None
    nvd_api_key: str = ""
    epss_enabled: bool | None = None
    epss_api_base: str | None = None
    intel_start_date: str | None = None


class AiIn(BaseModel):
    enabled: bool = True
    provider: str = "gemini"
    enrichment_mode: str = "direct"
    api_base: str = ""
    model: str = ""
    api_key: str = ""


class AssetConnectionIn(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = Field(default=443, ge=1, le=65535)
    use_tls: bool = True
    ignore_cert: bool = False
    username: str = ""
    password: str = ""
    api_path: str = ""


class CmdbIn(AssetConnectionIn):
    api_path: str = "/api"


class SonatypeIn(AssetConnectionIn):
    api_path: str = ""


class ItnmIn(AssetConnectionIn):
    api_path: str = "/api"
    list_path: str = "/devices"


class TicketingIn(BaseModel):
    enabled: bool = False
    enabled_jira: bool = False
    enabled_monday: bool = False
    enabled_email: bool = False
    enabled_custom: bool = False
    provider: str = "jira"
    host: str = ""
    port: int = Field(default=443, ge=1, le=65535)
    use_tls: bool = True
    ignore_cert: bool = False
    username: str = ""
    password: str = ""
    jira_user_email: str = ""
    jira_project_key: str = "VULN"
    jira_hunt_project_key: str = "HUNT"
    jira_issue_type: str = "Task"
    monday_board_id: str = ""
    monday_group_id: str = ""
    custom_api_path: str = "/api/tickets"
    custom_owner_project: str = "VULN"
    custom_hunt_project: str = "HUNT"
    hunt_email: str = ""
    fallback_owner_email: str = ""
    email_domains: str = ""
    smtp_host: str = ""
    smtp_port: int = Field(default=25, ge=1, le=65535)
    smtp_tls_mode: str = "plain"
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_ignore_cert: bool = False


class MessageTemplateIn(BaseModel):
    owner_subject: str = ""
    owner_body: str = ""
    hunt_subject: str = ""
    hunt_body: str = ""


def _asset_public(cfg: Any, name: str) -> dict[str, Any]:
    conn = getattr(cfg, f"{name}_connection")
    password = getattr(cfg, f"{name}_password", "") or getattr(cfg, f"{name}_api_token", "")
    return {
        "enabled": getattr(cfg, f"{name}_enabled", False),
        "host": getattr(cfg, f"{name}_host", ""),
        "port": getattr(cfg, f"{name}_port", 443),
        "use_tls": getattr(cfg, f"{name}_use_tls", True),
        "ignore_cert": getattr(cfg, f"{name}_ignore_cert", False),
        "username": getattr(cfg, f"{name}_username", ""),
        "password_set": bool(password),
        "api_path": getattr(cfg, f"{name}_api_path", ""),
        "base_url": conn.base_url,
    }


@router.put("/settings/enrichment")
def save_enrichment(body: EnrichmentIn) -> dict[str, Any]:
    updates: dict[str, str] = {}
    if body.enrichment_enabled is not None:
        updates["ENRICHMENT_ENABLED"] = "true" if body.enrichment_enabled else "false"
    if body.nvd_enabled is not None:
        updates["NVD_ENABLED"] = "true" if body.nvd_enabled else "false"
    if body.epss_enabled is not None:
        updates["EPSS_ENABLED"] = "true" if body.epss_enabled else "false"
    if body.nvd_api_base is not None:
        updates["NVD_API_BASE"] = body.nvd_api_base.strip()
    if body.epss_api_base is not None:
        updates["EPSS_API_BASE"] = body.epss_api_base.strip()
    if body.intel_start_date is not None:
        start = body.intel_start_date.strip()[:10]
        updates["INTEL_START_DATE"] = start or "2024-01-01"
    if body.nvd_api_key:
        updates["NVD_API_KEY"] = body.nvd_api_key
    if updates:
        save_env(updates)
    return {"ok": True, "updated": sorted(updates)}


@router.put("/settings/intel")
def save_intel_sources(body: IntelSourcesIn, db: Session = Depends(get_db)) -> dict[str, Any]:
    from app.services.intel_sources import public_intel_source, save_intel_sources

    if body.intel_start_date is not None:
        start = body.intel_start_date.strip()[:10]
        save_env({"INTEL_START_DATE": start or "2024-01-01"})
    rows = save_intel_sources(db, [item.model_dump() for item in body.sources])
    return {"ok": True, "sources": [public_intel_source(row) for row in rows]}


@router.post("/settings/intel/restore")
def restore_intel_sources(db: Session = Depends(get_db)) -> dict[str, Any]:
    from app.services.intel_sources import lookup_rows, public_intel_source, restore_default_intel_sources

    restore_default_intel_sources(db)
    return {"ok": True, "sources": [public_intel_source(row) for row in lookup_rows(db)]}


@router.put("/settings/ai")
def save_ai(body: AiIn) -> dict[str, Any]:
    provider = (body.provider or "gemini").strip().lower()
    if provider not in AI_PROVIDER_DEFAULTS:
        provider = "gemini"
    mode = (body.enrichment_mode or "direct").strip().lower()
    if mode not in {"direct", "org_llm"}:
        mode = "direct"
    default_base, default_model = AI_PROVIDER_DEFAULTS[provider]
    incoming_key = (body.api_key or "").strip()
    saved_key = (get_app_settings().ai_api_key or "").strip()
    has_key = bool(incoming_key or saved_key)
    enabled = bool(body.enabled) and has_key
    updates = {
        "AI_ENABLED": "true" if enabled else "false",
        "AI_PROVIDER": provider,
        "AI_ENRICHMENT_MODE": mode,
        "AI_API_BASE": body.api_base.strip() or default_base,
        "AI_MODEL": body.model.strip() or default_model,
    }
    if incoming_key:
        updates["AI_API_KEY"] = incoming_key
    save_env(updates)
    return {
        "ok": True,
        "enabled": enabled,
        "needs_key": bool(body.enabled) and not has_key,
    }


@router.put("/settings/assets/cmdb")
def save_cmdb(body: CmdbIn) -> dict[str, Any]:
    updates = {
        "CMDB_ENABLED": "true" if body.enabled else "false",
        "CMDB_HOST": body.host.strip(),
        "CMDB_PORT": str(body.port),
        "CMDB_USE_TLS": "true" if body.use_tls else "false",
        "CMDB_IGNORE_CERT": "true" if body.ignore_cert else "false",
        "CMDB_USERNAME": body.username.strip(),
        "CMDB_API_PATH": body.api_path.strip() or "/api",
    }
    if body.password:
        updates["CMDB_PASSWORD"] = body.password
    save_env(updates)
    return {"ok": True}


@router.put("/settings/assets/sonatype")
def save_sonatype(body: SonatypeIn) -> dict[str, Any]:
    updates = {
        "SONATYPE_ENABLED": "true" if body.enabled else "false",
        "SONATYPE_HOST": body.host.strip(),
        "SONATYPE_PORT": str(body.port),
        "SONATYPE_USE_TLS": "true" if body.use_tls else "false",
        "SONATYPE_IGNORE_CERT": "true" if body.ignore_cert else "false",
        "SONATYPE_USERNAME": body.username.strip(),
        "SONATYPE_API_PATH": body.api_path.strip(),
    }
    if body.password:
        updates["SONATYPE_PASSWORD"] = body.password
    save_env(updates)
    started = False
    if body.enabled:
        from app.services.inventory_sync import start_sonatype_sync

        start_sonatype_sync()
        started = True
    return {"ok": True, "sync_started": started}


@router.put("/settings/assets/itnm")
def save_itnm(body: ItnmIn) -> dict[str, Any]:
    updates = {
        "ITNM_ENABLED": "true" if body.enabled else "false",
        "ITNM_HOST": body.host.strip(),
        "ITNM_PORT": str(body.port),
        "ITNM_USE_TLS": "true" if body.use_tls else "false",
        "ITNM_IGNORE_CERT": "true" if body.ignore_cert else "false",
        "ITNM_USERNAME": body.username.strip(),
        "ITNM_API_PATH": body.api_path.strip() or "/api",
        "ITNM_LIST_PATH": body.list_path.strip() or "/devices",
    }
    if body.password:
        updates["ITNM_PASSWORD"] = body.password
    save_env(updates)
    return {"ok": True}


@router.post("/settings/assets/cmdb/test")
async def test_cmdb() -> dict[str, Any]:
    from app.utils.integration_connection import probe_connection

    cfg = get_app_settings()
    conn = cfg.cmdb_connection
    if not conn.base_url:
        raise HTTPException(400, "CMDB host is required")
    try:
        return await probe_connection(conn, "/assets")
    except Exception as exc:
        raise HTTPException(400, f"CMDB connection failed: {exc}") from exc


@router.post("/settings/assets/sonatype/test")
async def test_sonatype() -> dict[str, Any]:
    from app.utils.integration_connection import probe_connection

    cfg = get_app_settings()
    conn = cfg.sonatype_connection
    if not conn.base_url:
        raise HTTPException(400, "Sonatype host is required")
    try:
        return await probe_connection(conn, "/api/v2/applications")
    except Exception as exc:
        raise HTTPException(400, f"Sonatype connection failed: {exc}") from exc


@router.post("/settings/assets/itnm/test")
async def test_itnm() -> dict[str, Any]:
    from app.utils.integration_connection import probe_connection

    cfg = get_app_settings()
    conn = cfg.itnm_connection
    if not conn.base_url:
        raise HTTPException(400, "ITNM / discovery host is required")
    try:
        return await probe_connection(conn, cfg.itnm_list_path or "/devices")
    except Exception as exc:
        raise HTTPException(400, f"ITNM connection failed: {exc}") from exc


@router.put("/settings/ticketing")
def save_ticketing(body: TicketingIn) -> dict[str, Any]:
    provider = (body.provider or "jira").strip().lower()
    if provider not in {"jira", "monday", "custom", "email"}:
        provider = "jira"
    flags = {
        "jira": body.enabled_jira,
        "monday": body.enabled_monday,
        "email": body.enabled_email,
        "custom": body.enabled_custom,
    }
    if not any(flags.values()) and body.enabled:
        flags[provider] = True
    any_on = any(flags.values())
    if flags.get(provider):
        stored_provider = provider
    else:
        stored_provider = next((name for name in ("jira", "monday", "email", "custom") if flags[name]), "jira")
    updates = {
        "TICKETING_ENABLED": "true" if any_on else "false",
        "TICKETING_PROVIDER": stored_provider,
        "TICKETING_JIRA_ENABLED": "true" if flags["jira"] else "false",
        "TICKETING_MONDAY_ENABLED": "true" if flags["monday"] else "false",
        "TICKETING_EMAIL_ENABLED": "true" if flags["email"] else "false",
        "TICKETING_CUSTOM_ENABLED": "true" if flags["custom"] else "false",
        "TICKETING_HOST": body.host.strip(),
        "TICKETING_PORT": str(body.port),
        "TICKETING_USE_TLS": "true" if body.use_tls else "false",
        "TICKETING_IGNORE_CERT": "true" if body.ignore_cert else "false",
        "TICKETING_USERNAME": body.username.strip(),
        "JIRA_USER_EMAIL": body.jira_user_email.strip() or body.username.strip(),
        "JIRA_PROJECT_KEY": body.jira_project_key.strip() or "VULN",
        "JIRA_HUNT_PROJECT_KEY": body.jira_hunt_project_key.strip() or "HUNT",
        "JIRA_ISSUE_TYPE": body.jira_issue_type.strip() or "Task",
        "MONDAY_BOARD_ID": body.monday_board_id.strip(),
        "MONDAY_GROUP_ID": body.monday_group_id.strip(),
        "CUSTOM_TICKETING_API_PATH": body.custom_api_path.strip() or "/api/tickets",
        "CUSTOM_OWNER_PROJECT": body.custom_owner_project.strip() or "VULN",
        "CUSTOM_HUNT_PROJECT": body.custom_hunt_project.strip() or "HUNT",
        "TICKETING_HUNT_EMAIL": body.hunt_email.strip(),
        "TICKETING_FALLBACK_OWNER_EMAIL": body.fallback_owner_email.strip(),
        "TICKETING_EMAIL_DOMAINS": body.email_domains.strip() or " ",
        "SMTP_RELAY_HOST": body.smtp_host.strip(),
        "SMTP_RELAY_PORT": str(body.smtp_port),
        "SMTP_RELAY_USERNAME": body.smtp_username.strip(),
        "SMTP_RELAY_FROM": body.smtp_from.strip(),
        "SMTP_RELAY_IGNORE_CERT": "true" if body.smtp_ignore_cert else "false",
    }
    mode = (body.smtp_tls_mode or "plain").strip().lower()
    if mode not in {"plain", "starttls", "ssl"}:
        mode = "plain"
    updates["SMTP_RELAY_TLS_MODE"] = mode
    updates["SMTP_RELAY_USE_TLS"] = "true" if mode == "starttls" else "false"
    updates["SMTP_RELAY_USE_SSL"] = "true" if mode == "ssl" else "false"
    if body.password:
        updates["TICKETING_PASSWORD"] = body.password
        if flags["jira"]:
            updates["JIRA_API_TOKEN"] = body.password
    if body.smtp_password:
        updates["SMTP_RELAY_PASSWORD"] = body.smtp_password
    save_env(updates)
    return {"ok": True}


@router.post("/settings/ticketing/test")
async def test_ticketing(provider: str | None = Query(None)) -> dict[str, Any]:
    import smtplib

    import httpx

    from app.config import enabled_ticketing_providers
    from app.utils.integration_connection import probe_connection

    cfg = get_app_settings()
    enabled = enabled_ticketing_providers(cfg)
    requested = (provider or "").strip().lower()
    if requested not in {"jira", "monday", "custom", "email"}:
        requested = enabled[0] if enabled else (cfg.ticketing_provider or "jira").lower()
    if requested not in enabled:
        raise HTTPException(400, f"{requested.title()} ticketing is disabled")
    conn = cfg.ticketing_connection
    if not conn.base_url and requested not in {"monday", "email"}:
        raise HTTPException(400, "Ticketing host is required")
    try:
        if requested == "jira":
            return await probe_connection(conn, "/rest/api/3/myself")
        if requested == "monday":
            token = cfg.ticketing_password or cfg.jira_api_token
            if not token:
                raise HTTPException(400, "Monday API token is required")
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.post(
                    "https://api.monday.com/v2",
                    json={"query": "{ me { id name } }"},
                    headers={"Authorization": token, "Content-Type": "application/json"},
                )
                response.raise_for_status()
                return {"ok": True, "status": response.status_code, "provider": "monday"}
        if requested == "email":
            from app.integrations.smtp_relay import SmtpRelayClient

            relay = SmtpRelayClient(cfg)
            if relay.configured:
                return relay.send_test()
            from app.integrations.exchange import ExchangeClient

            return ExchangeClient.from_app().probe()
        return await probe_connection(conn, cfg.custom_ticketing_api_path or "/")
    except smtplib.SMTPAuthenticationError:
        user = (getattr(cfg, "smtp_relay_username", "") or "").strip() or "(no username)"
        host = (getattr(cfg, "smtp_relay_host", "") or "").strip() or "SMTP server"
        raise HTTPException(
            400,
            f"{host} rejected the login for {user}. "
            "The username must be the mailbox that owns this password. "
            "Restart EVulnTasker after changing code, then Save and Test again.",
        ) from None
    except Exception as exc:
        raise HTTPException(400, f"Ticketing test failed: {exc}") from None


@router.get("/settings/message")
def get_message_templates() -> dict[str, Any]:
    from app.services.mail_templates import SAMPLE_CONTEXT, load_templates, tokens_payload

    templates = load_templates()
    return {
        "templates": templates,
        "tokens": tokens_payload(),
        "sample": SAMPLE_CONTEXT,
    }


@router.put("/settings/message")
def save_message_templates(body: MessageTemplateIn) -> dict[str, Any]:
    from app.services.mail_templates import save_templates

    templates = save_templates(body.model_dump())
    return {"ok": True, "templates": templates}


@router.post("/settings/message/preview")
def preview_message_templates(body: MessageTemplateIn) -> dict[str, Any]:
    from app.services.mail_templates import SAMPLE_CONTEXT, load_templates, render_template

    templates = load_templates()
    data = body.model_dump()
    for key, value in data.items():
        if isinstance(value, str) and value.strip():
            templates[key] = value
    return {
        "owner_subject": render_template(templates["owner_subject"], SAMPLE_CONTEXT),
        "owner_body": render_template(templates["owner_body"], SAMPLE_CONTEXT),
        "hunt_subject": render_template(templates["hunt_subject"], SAMPLE_CONTEXT),
        "hunt_body": render_template(templates["hunt_body"], SAMPLE_CONTEXT),
        "sample": SAMPLE_CONTEXT,
    }


def _reset_internal_systems(db: Session) -> dict[str, Any]:
    from app.services.wipe import wipe_internal_systems

    try:
        return wipe_internal_systems(db)
    except Exception as exc:
        raise HTTPException(500, f"Internal systems reset failed: {exc}") from exc


@router.post("/settings/reset-system")
def reset_system(db: Session = Depends(get_db)) -> dict[str, Any]:
    return _reset_internal_systems(db)


@router.post("/settings/reset-internal-systems")
def reset_internal_systems(db: Session = Depends(get_db)) -> dict[str, Any]:
    return _reset_internal_systems(db)


@router.post("/settings/wipe-cve-data")
def wipe_cve_data(db: Session = Depends(get_db)) -> dict[str, Any]:
    from app.services.wipe import wipe_collected_cve_data

    try:
        return wipe_collected_cve_data(db)
    except Exception as exc:
        raise HTTPException(500, f"CVE wipe failed: {exc}") from exc


def assets_payload(cfg: Any) -> dict[str, Any]:
    itnm = _asset_public(cfg, "itnm")
    itnm["list_path"] = getattr(cfg, "itnm_list_path", "/devices")
    return {
        "cmdb": _asset_public(cfg, "cmdb"),
        "sonatype": _asset_public(cfg, "sonatype"),
        "itnm": itnm,
        "sync": {
            "enabled": bool(getattr(cfg, "inventory_sync_enabled", False)),
            "seconds": int(getattr(cfg, "inventory_sync_seconds", 86400) or 86400),
        },
    }


def ticketing_payload(cfg: Any) -> dict[str, Any]:
    from app.config import enabled_ticketing_providers

    conn = cfg.ticketing_connection
    password = cfg.ticketing_password or cfg.jira_api_token
    enabled = enabled_ticketing_providers(cfg)
    return {
        "enabled": bool(enabled),
        "enables": {
            "jira": "jira" in enabled,
            "monday": "monday" in enabled,
            "email": "email" in enabled,
            "custom": "custom" in enabled,
        },
        "provider": cfg.ticketing_provider,
        "host": cfg.ticketing_host,
        "port": cfg.ticketing_port,
        "use_tls": cfg.ticketing_use_tls,
        "ignore_cert": cfg.ticketing_ignore_cert,
        "username": cfg.ticketing_username or cfg.jira_user_email,
        "password_set": bool(password),
        "base_url": conn.base_url,
        "jira_user_email": cfg.jira_user_email,
        "jira_project_key": cfg.jira_project_key,
        "jira_hunt_project_key": cfg.jira_hunt_project_key,
        "jira_issue_type": cfg.jira_issue_type,
        "monday_board_id": cfg.monday_board_id,
        "monday_group_id": cfg.monday_group_id,
        "custom_api_path": cfg.custom_ticketing_api_path,
        "custom_owner_project": cfg.custom_owner_project,
        "custom_hunt_project": cfg.custom_hunt_project,
        "hunt_email": cfg.ticketing_hunt_email,
        "fallback_owner_email": cfg.ticketing_fallback_owner_email,
        "email_domains": cfg.ticketing_email_domains,
        "configured": cfg.ticketing_configured,
        "smtp_host": cfg.smtp_relay_host,
        "smtp_port": cfg.smtp_relay_port,
        "smtp_tls_mode": cfg.smtp_relay_tls_mode or "plain",
        "smtp_username": cfg.smtp_relay_username,
        "smtp_from": cfg.smtp_relay_from,
        "smtp_ignore_cert": cfg.smtp_relay_ignore_cert,
        "smtp_password_set": bool(cfg.smtp_relay_password),
    }
