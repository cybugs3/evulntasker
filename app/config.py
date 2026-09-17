"""
Central configuration loaded from environment / .env via pydantic-settings.

The same settings object is used by the API process, the asyncio worker,
and (optionally) a Celery worker so behaviour stays consistent across
deployment modes.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"

TICKETING_PROVIDER_NAMES = ("jira", "monday", "email", "custom")
APP_ENV_PREFIX = "EVULNTASKER"
LEGACY_ENV_PREFIX = "VULNINTEL"


def app_env_choices(suffix: str) -> AliasChoices:
    """Prefer EVULNTASKER_* and still accept VULNINTEL_* from older .env files."""
    return AliasChoices(f"{APP_ENV_PREFIX}_{suffix}", f"{LEGACY_ENV_PREFIX}_{suffix}")


def enabled_ticketing_providers(settings: Any) -> list[str]:
    """Providers with their own Enable switch on. Falls back to the old single provider flag."""
    chosen = [
        name
        for name in TICKETING_PROVIDER_NAMES
        if bool(getattr(settings, f"ticketing_{name}_enabled", False))
    ]
    if chosen:
        return chosen
    if not bool(getattr(settings, "ticketing_enabled", False)):
        return []
    provider = (getattr(settings, "ticketing_provider", None) or "jira").strip().lower()
    if provider in TICKETING_PROVIDER_NAMES:
        return [provider]
    return ["jira"]


class Settings(BaseSettings):
    """Application settings. Runtime keys use EVULNTASKER_* and still accept
    VULNINTEL_* from older .env files. Integration names (NVD_*, JIRA_*, …)
    are unchanged."""

    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    env: Literal["development", "staging", "production"] = Field(
        default="development", validation_alias=app_env_choices("ENV")
    )
    secret_key: str = Field(
        default="change-me-in-production", validation_alias=app_env_choices("SECRET_KEY")
    )
    basic_auth_user: str = Field(default="", validation_alias=app_env_choices("BASIC_AUTH_USER"))
    basic_auth_password: str = Field(
        default="", validation_alias=app_env_choices("BASIC_AUTH_PASSWORD")
    )
    local_ingest_allow: str = Field(
        default="", validation_alias=app_env_choices("LOCAL_INGEST_ALLOW")
    )
    host: str = Field(default="0.0.0.0", validation_alias=app_env_choices("HOST"))
    port: int = Field(default=8080, validation_alias=app_env_choices("PORT"))
    log_level: str = Field(default="INFO", validation_alias=app_env_choices("LOG_LEVEL"))
    log_dir: Path = Field(default=Path("./logs"), validation_alias=app_env_choices("LOG_DIR"))

    database_url: str = Field(
        default="sqlite:///./data/evulntasker.db",
        validation_alias=app_env_choices("DATABASE_URL"),
    )

    feed_poll_seconds: int = Field(default=300, validation_alias=app_env_choices("FEED_POLL_SECONDS"))
    email_poll_seconds: int = Field(default=120, validation_alias=app_env_choices("EMAIL_POLL_SECONDS"))
    worker_poll_seconds: int = Field(default=2, validation_alias=app_env_choices("WORKER_POLL_SECONDS"))
    enrichment_retry_seconds: int = Field(default=120, alias="ENRICHMENT_RETRY_SECONDS")

    enrichment_enabled: bool = Field(default=True, alias="ENRICHMENT_ENABLED")
    nvd_api_base: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0", alias="NVD_API_BASE"
    )
    nvd_api_key: str = Field(default="", alias="NVD_API_KEY")
    nvd_enabled: bool = Field(default=False, alias="NVD_ENABLED")
    intel_start_date: str = Field(default="2024-01-01", alias="INTEL_START_DATE")
    intel_sources_seeded: bool = Field(default=False, alias="INTEL_SOURCES_SEEDED")
    atom_feeds_seeded: bool = Field(default=False, alias="ATOM_FEEDS_SEEDED")
    atom_lookups_seeded: bool = Field(default=False, alias="ATOM_LOOKUPS_SEEDED")

    epss_enabled: bool = Field(default=False, alias="EPSS_ENABLED")
    epss_api_base: str = Field(
        default="https://api.first.org/data/v1/epss", alias="EPSS_API_BASE"
    )

    jira_base_url: str = Field(default="", alias="JIRA_BASE_URL")
    jira_user_email: str = Field(default="", alias="JIRA_USER_EMAIL")
    jira_api_token: str = Field(default="", alias="JIRA_API_TOKEN")
    jira_project_key: str = Field(default="VULN", alias="JIRA_PROJECT_KEY")
    jira_hunt_project_key: str = Field(default="HUNT", alias="JIRA_HUNT_PROJECT_KEY")
    jira_issue_type: str = Field(default="Task", alias="JIRA_ISSUE_TYPE")

    ticketing_enabled: bool = Field(default=False, alias="TICKETING_ENABLED")
    ticketing_provider: str = Field(default="jira", alias="TICKETING_PROVIDER")
    ticketing_jira_enabled: bool = Field(default=False, alias="TICKETING_JIRA_ENABLED")
    ticketing_monday_enabled: bool = Field(default=False, alias="TICKETING_MONDAY_ENABLED")
    ticketing_email_enabled: bool = Field(default=False, alias="TICKETING_EMAIL_ENABLED")
    ticketing_custom_enabled: bool = Field(default=False, alias="TICKETING_CUSTOM_ENABLED")
    ticketing_host: str = Field(default="", alias="TICKETING_HOST")
    ticketing_port: int = Field(default=443, alias="TICKETING_PORT")
    ticketing_use_tls: bool = Field(default=True, alias="TICKETING_USE_TLS")
    ticketing_ignore_cert: bool = Field(default=False, alias="TICKETING_IGNORE_CERT")
    ticketing_username: str = Field(default="", alias="TICKETING_USERNAME")
    ticketing_password: str = Field(default="", alias="TICKETING_PASSWORD")
    monday_board_id: str = Field(default="", alias="MONDAY_BOARD_ID")
    monday_group_id: str = Field(default="", alias="MONDAY_GROUP_ID")
    custom_ticketing_api_path: str = Field(default="/api/tickets", alias="CUSTOM_TICKETING_API_PATH")
    custom_owner_project: str = Field(default="VULN", alias="CUSTOM_OWNER_PROJECT")
    custom_hunt_project: str = Field(default="HUNT", alias="CUSTOM_HUNT_PROJECT")
    ticketing_hunt_email: str = Field(default="", alias="TICKETING_HUNT_EMAIL")
    ticketing_fallback_owner_email: str = Field(
        default="", alias="TICKETING_FALLBACK_OWNER_EMAIL"
    )
    ticketing_email_domains: str = Field(default="", alias="TICKETING_EMAIL_DOMAINS")

    smtp_relay_host: str = Field(default="", alias="SMTP_RELAY_HOST")
    smtp_relay_port: int = Field(default=25, alias="SMTP_RELAY_PORT")
    smtp_relay_tls_mode: str = Field(default="plain", alias="SMTP_RELAY_TLS_MODE")
    smtp_relay_use_tls: bool = Field(default=False, alias="SMTP_RELAY_USE_TLS")
    smtp_relay_use_ssl: bool = Field(default=False, alias="SMTP_RELAY_USE_SSL")
    smtp_relay_username: str = Field(default="", alias="SMTP_RELAY_USERNAME")
    smtp_relay_password: str = Field(default="", alias="SMTP_RELAY_PASSWORD")
    smtp_relay_from: str = Field(default="", alias="SMTP_RELAY_FROM")
    smtp_relay_ignore_cert: bool = Field(default=False, alias="SMTP_RELAY_IGNORE_CERT")

    gmail_sender_email: str = Field(default="", alias="GMAIL_SENDER_EMAIL")
    gmail_app_password: str = Field(default="", alias="GMAIL_APP_PASSWORD")
    gmail_receiver_email: str = Field(default="", alias="GMAIL_RECEIVER_EMAIL")

    exchange_server: str = Field(default="", alias="EXCHANGE_SERVER")
    exchange_username: str = Field(default="", alias="EXCHANGE_USERNAME")
    exchange_password: str = Field(default="", alias="EXCHANGE_PASSWORD")
    exchange_email: str = Field(default="", alias="EXCHANGE_EMAIL")
    exchange_folder: str = Field(default="Inbox", alias="EXCHANGE_FOLDER")

    cmdb_enabled: bool = Field(default=False, alias="CMDB_ENABLED")
    cmdb_host: str = Field(default="", alias="CMDB_HOST")
    cmdb_port: int = Field(default=443, alias="CMDB_PORT")
    cmdb_use_tls: bool = Field(default=True, alias="CMDB_USE_TLS")
    cmdb_ignore_cert: bool = Field(default=False, alias="CMDB_IGNORE_CERT")
    cmdb_username: str = Field(default="", alias="CMDB_USERNAME")
    cmdb_password: str = Field(default="", alias="CMDB_PASSWORD")
    cmdb_api_path: str = Field(default="/api", alias="CMDB_API_PATH")
    cmdb_api_url: str = Field(default="", alias="CMDB_API_URL")
    cmdb_api_token: str = Field(default="", alias="CMDB_API_TOKEN")

    sonatype_enabled: bool = Field(default=False, alias="SONATYPE_ENABLED")
    sonatype_host: str = Field(default="", alias="SONATYPE_HOST")
    sonatype_port: int = Field(default=8070, alias="SONATYPE_PORT")
    sonatype_use_tls: bool = Field(default=True, alias="SONATYPE_USE_TLS")
    sonatype_ignore_cert: bool = Field(default=False, alias="SONATYPE_IGNORE_CERT")
    sonatype_username: str = Field(default="", alias="SONATYPE_USERNAME")
    sonatype_password: str = Field(default="", alias="SONATYPE_PASSWORD")
    sonatype_api_path: str = Field(default="", alias="SONATYPE_API_PATH")
    sonatype_api_url: str = Field(default="", alias="SONATYPE_API_URL")
    sonatype_api_token: str = Field(default="", alias="SONATYPE_API_TOKEN")

    itnm_enabled: bool = Field(default=False, alias="ITNM_ENABLED")
    itnm_host: str = Field(default="", alias="ITNM_HOST")
    itnm_port: int = Field(default=443, alias="ITNM_PORT")
    itnm_use_tls: bool = Field(default=True, alias="ITNM_USE_TLS")
    itnm_ignore_cert: bool = Field(default=False, alias="ITNM_IGNORE_CERT")
    itnm_username: str = Field(default="", alias="ITNM_USERNAME")
    itnm_password: str = Field(default="", alias="ITNM_PASSWORD")
    itnm_api_path: str = Field(default="/api", alias="ITNM_API_PATH")
    itnm_api_url: str = Field(default="", alias="ITNM_API_URL")
    itnm_list_path: str = Field(default="/devices", alias="ITNM_LIST_PATH")

    inventory_sync_enabled: bool = Field(default=False, alias="INVENTORY_SYNC_ENABLED")
    inventory_sync_seconds: int = Field(default=86400, alias="INVENTORY_SYNC_SECONDS")

    ai_enabled: bool = Field(default=False, alias="AI_ENABLED")
    ai_provider: str = Field(default="gemini", alias="AI_PROVIDER")
    ai_enrichment_mode: str = Field(default="direct", alias="AI_ENRICHMENT_MODE")
    ai_api_base: str = Field(
        default="https://generativelanguage.googleapis.com/v1beta/openai",
        alias="AI_API_BASE",
    )
    ai_api_key: str = Field(default="", alias="AI_API_KEY")
    ai_model: str = Field(default="gemini-1.5-flash", alias="AI_MODEL")

    celery_broker_url: str = Field(
        default="redis://127.0.0.1:6379/0", alias="CELERY_BROKER_URL"
    )
    celery_result_backend: str = Field(
        default="redis://127.0.0.1:6379/1", alias="CELERY_RESULT_BACKEND"
    )

    @field_validator("log_dir", mode="before")
    @classmethod
    def _as_path(cls, value: str | Path) -> Path:
        return Path(value)

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def jira_configured(self) -> bool:
        if "jira" not in enabled_ticketing_providers(self):
            return False
        token = self.jira_api_token or self.ticketing_password
        base = self.ticketing_base_url or self.jira_base_url
        return bool(base and token)

    @property
    def ticketing_configured(self) -> bool:
        enabled = enabled_ticketing_providers(self)
        if not enabled:
            return False
        if "email" in enabled:
            from app.integrations.smtp_relay import SmtpRelayClient

            if SmtpRelayClient(self).configured:
                return True
            from app.integrations.exchange import ExchangeClient

            if ExchangeClient.from_app().can_send():
                return True
        if "monday" in enabled:
            token = self.ticketing_password or self.jira_api_token
            if token and self.monday_board_id:
                return True
        if "jira" in enabled and self.jira_configured:
            return True
        if "custom" in enabled:
            conn = self.ticketing_connection
            if conn.configured and bool(conn.password or conn.username):
                return True
        return False

    @property
    def ticketing_base_url(self) -> str:
        return self.ticketing_connection.base_url or self.jira_base_url

    @property
    def cmdb_connection(self):
        from app.utils.integration_connection import IntegrationConnection

        password = self.cmdb_password or self.cmdb_api_token
        return IntegrationConnection(
            enabled=self.cmdb_enabled,
            host=self.cmdb_host,
            port=self.cmdb_port,
            use_tls=self.cmdb_use_tls,
            ignore_cert=self.cmdb_ignore_cert,
            username=self.cmdb_username,
            password=password,
            api_path=self.cmdb_api_path,
            legacy_url=self.cmdb_api_url,
        )

    @property
    def sonatype_connection(self):
        from app.utils.integration_connection import IntegrationConnection

        password = self.sonatype_password or self.sonatype_api_token
        return IntegrationConnection(
            enabled=self.sonatype_enabled,
            host=self.sonatype_host,
            port=self.sonatype_port,
            use_tls=self.sonatype_use_tls,
            ignore_cert=self.sonatype_ignore_cert,
            username=self.sonatype_username,
            password=password,
            api_path=self.sonatype_api_path,
            legacy_url=self.sonatype_api_url,
        )

    @property
    def itnm_connection(self):
        from app.utils.integration_connection import IntegrationConnection

        return IntegrationConnection(
            enabled=self.itnm_enabled,
            host=self.itnm_host,
            port=self.itnm_port,
            use_tls=self.itnm_use_tls,
            ignore_cert=self.itnm_ignore_cert,
            username=self.itnm_username,
            password=self.itnm_password,
            api_path=self.itnm_api_path,
            legacy_url=self.itnm_api_url,
        )

    @property
    def ticketing_connection(self):
        from app.utils.integration_connection import IntegrationConnection

        password = self.ticketing_password or self.jira_api_token
        username = self.ticketing_username or self.jira_user_email
        api_path = ""
        enabled = enabled_ticketing_providers(self)
        provider = (self.ticketing_provider or "jira").lower()
        if "custom" in enabled and "jira" not in enabled:
            api_path = self.custom_ticketing_api_path
        elif not enabled and provider == "custom":
            api_path = self.custom_ticketing_api_path
        return IntegrationConnection(
            enabled=bool({"jira", "custom"} & set(enabled)),
            host=self.ticketing_host,
            port=self.ticketing_port,
            use_tls=self.ticketing_use_tls,
            ignore_cert=self.ticketing_ignore_cert,
            username=username,
            password=password,
            api_path=api_path,
            legacy_url=self.jira_base_url,
        )

    @property
    def gmail_configured(self) -> bool:
        return bool(
            (self.gmail_sender_email or "").strip()
            and (self.gmail_app_password or "").strip()
            and (self.gmail_receiver_email or "").strip()
        )

    @property
    def exchange_configured(self) -> bool:
        return bool(self.exchange_server and self.exchange_username)

    @property
    def ai_configured(self) -> bool:
        """True only when the operator turned AI on *and* saved an API key."""
        return bool(self.ai_enabled) and bool((self.ai_api_key or "").strip())

    @property
    def ai_enrichment_direct(self) -> bool:
        return (self.ai_enrichment_mode or "direct").lower() == "direct"

    @property
    def nvd_configured(self) -> bool:
        return bool(self.enrichment_enabled and self.nvd_enabled and self.nvd_api_base)

    @property
    def epss_configured(self) -> bool:
        return bool(self.enrichment_enabled and self.epss_enabled and self.epss_api_base)


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton — call get_settings.cache_clear() in tests."""
    return Settings()
