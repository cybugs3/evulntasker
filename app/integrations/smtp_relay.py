"""SMTP mail relay for outbound owner / hunt tasks (lab and external recipients)."""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

from app.config import Settings, get_settings

log = logging.getLogger(__name__)


class SmtpRelayClient:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    @classmethod
    def from_app(cls) -> "SmtpRelayClient":
        return cls(get_settings())

    @property
    def host(self) -> str:
        return str(getattr(self.settings, "smtp_relay_host", "") or "").strip()

    @property
    def port(self) -> int:
        try:
            return int(getattr(self.settings, "smtp_relay_port", 25) or 25)
        except (TypeError, ValueError):
            return 25

    @property
    def mode(self) -> str:
        raw = str(getattr(self.settings, "smtp_relay_tls_mode", "") or "").strip().lower()
        if raw in {"plain", "starttls", "ssl"}:
            return raw
        if getattr(self.settings, "smtp_relay_use_ssl", False):
            return "ssl"
        if getattr(self.settings, "smtp_relay_use_tls", False):
            return "starttls"
        return "plain"

    @property
    def username(self) -> str:
        return str(getattr(self.settings, "smtp_relay_username", "") or "").strip()

    @property
    def password(self) -> str:
        return str(getattr(self.settings, "smtp_relay_password", "") or "")

    @property
    def from_addr(self) -> str:
        return (
            str(getattr(self.settings, "smtp_relay_from", "") or "").strip()
            or self.username
            or "evulntasker@localhost"
        )

    @property
    def ignore_cert(self) -> bool:
        return bool(getattr(self.settings, "smtp_relay_ignore_cert", False))

    @property
    def configured(self) -> bool:
        return bool(self.host)

    def _ssl_context(self) -> ssl.SSLContext:
        if self.ignore_cert:
            return ssl._create_unverified_context()
        return ssl.create_default_context()

    def _connect(self) -> smtplib.SMTP:
        context = self._ssl_context()
        mode = self.mode
        if mode == "ssl" or self.port == 465:
            client = smtplib.SMTP_SSL(self.host, self.port, timeout=20, context=context)
        else:
            client = smtplib.SMTP(self.host, self.port, timeout=20)
            if mode == "starttls":
                client.starttls(context=context)
        if self.username:
            client.login(self.username, self.password)
        return client

    def probe(self) -> dict[str, Any]:
        if not self.configured:
            raise RuntimeError("SMTP relay host is required")
        client = self._connect()
        try:
            status = client.noop()
        finally:
            try:
                client.quit()
            except Exception:
                client.close()
        return {
            "ok": True,
            "provider": "smtp",
            "host": self.host,
            "port": self.port,
            "mode": self.mode,
            "from": self.from_addr,
            "status": status[0] if isinstance(status, tuple) else status,
        }

    def send(self, *, to: list[str] | str, subject: str, body: str) -> dict[str, Any]:
        recipients = [to] if isinstance(to, str) else [addr for addr in to if addr]
        recipients = [addr.strip() for addr in recipients if addr and addr.strip()]
        payload = {
            "to": recipients,
            "subject": subject,
            "from": self.from_addr,
        }
        if not self.configured or not recipients:
            log.info("SMTP dry-run: would send %s to %s", subject, recipients or "(no recipient)")
            return {"dry_run": True, **payload}

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self.from_addr
        message["To"] = ", ".join(recipients)
        message.set_content(body or "")

        client = self._connect()
        try:
            client.send_message(message)
        finally:
            try:
                client.quit()
            except Exception:
                client.close()
        log.info("SMTP sent %s to %s via %s:%s", subject, recipients, self.host, self.port)
        return {"dry_run": False, **payload}
