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
        if raw not in {"plain", "starttls", "ssl"}:
            if getattr(self.settings, "smtp_relay_use_ssl", False):
                raw = "ssl"
            elif getattr(self.settings, "smtp_relay_use_tls", False):
                raw = "starttls"
            else:
                raw = "plain"
        host = self.host.lower()
        if "gmail.com" in host and raw == "plain":
            return "ssl" if self.port == 465 else "starttls"
        return raw

    @property
    def username(self) -> str:
        return str(getattr(self.settings, "smtp_relay_username", "") or "").strip()

    @property
    def password(self) -> str:
        # Gmail App Passwords are often copied with spaces; SMTP AUTH rejects them.
        return "".join(str(getattr(self.settings, "smtp_relay_password", "") or "").split())

    @property
    def from_addr(self) -> str:
        return (
            str(getattr(self.settings, "smtp_relay_from", "") or "").strip()
            or self.username
            or "evulntasker@localhost"
        )

    def _gmail_host(self) -> bool:
        return "gmail.com" in self.host.lower()

    def _header_from(self, sender: str | None = None) -> str:
        """Address shown to recipients. Honor Settings → From; do not rewrite it to Username."""
        return (sender or self.from_addr).strip() or self.from_addr

    def _envelope_from(self, header_from: str) -> str:
        """Gmail SMTP AUTH still requires MAIL FROM of the logged-in mailbox."""
        if self._gmail_host() and "@" in self.username:
            return self.username
        return header_from

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
        if self.username and not self.password:
            raise RuntimeError(
                "SMTP username is set but no password is stored. "
                "Paste the password, click Save, then Test."
            )
        context = self._ssl_context()
        mode = self.mode
        if mode == "ssl" or self.port == 465:
            client = smtplib.SMTP_SSL(self.host, self.port, timeout=20, context=context)
        else:
            client = smtplib.SMTP(self.host, self.port, timeout=20)
            if mode == "starttls" or self.port == 587:
                client.ehlo()
                client.starttls(context=context)
                client.ehlo()
        if self.username:
            try:
                client.login(self.username, self.password)
            except smtplib.SMTPAuthenticationError as exc:
                raise RuntimeError(
                    f"{self.host} rejected the login for {self.username}. "
                    "Check the username and password. Some providers require an app-specific "
                    "password instead of the normal account password."
                ) from exc
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
            "username": self.username,
            "password_set": bool(self.password),
            "from": self.from_addr,
            "status": status[0] if isinstance(status, tuple) else status,
        }

    def test_recipient(self) -> str:
        """Mailbox that should receive the Settings test message."""
        hunt = str(getattr(self.settings, "ticketing_hunt_email", "") or "").strip()
        fallback = str(getattr(self.settings, "ticketing_fallback_owner_email", "") or "").strip()
        for value in (self.username, self.from_addr, hunt, fallback):
            addr = (value or "").strip()
            if "@" in addr and addr.lower() not in {"evulntasker@localhost"}:
                return addr
        return ""

    def send_test(self) -> dict[str, Any]:
        """Login and send a short test message so the operator can confirm delivery."""
        to = self.test_recipient()
        if not to:
            raise RuntimeError(
                "SMTP host is set, but there is no mailbox to send a test to. "
                "Set Username, From, Permanent email, or Fallback owner email to a real address."
            )
        sender = self._header_from()
        sent = self.send(
            to=to,
            subject="[EVulnTasker] SMTP test",
            body=(
                "EVulnTasker sent this message to confirm the SMTP settings work.\n\n"
                f"Host: {self.host}:{self.port} ({self.mode})\n"
                f"Authenticated as: {self.username or '(anonymous)'}\n"
                f"From: {sender}\n"
            ),
            sender=sender,
        )
        if sent.get("dry_run"):
            raise RuntimeError(f"SMTP test did not send. Check host and recipient ({to}).")
        result = {
            "ok": True,
            "provider": "smtp",
            "host": self.host,
            "port": self.port,
            "mode": self.mode,
            "username": self.username,
            "password_set": bool(self.password),
            "from": sender,
            "to": to,
            "sent": True,
            "status": 250,
        }
        return result

    def send(
        self,
        *,
        to: list[str] | str,
        subject: str,
        body: str,
        sender: str | None = None,
    ) -> dict[str, Any]:
        recipients = [to] if isinstance(to, str) else [addr for addr in to if addr]
        recipients = [addr.strip() for addr in recipients if addr and addr.strip()]
        from_addr = self._header_from(sender)
        envelope = self._envelope_from(from_addr)
        payload = {
            "to": recipients,
            "subject": subject,
            "from": from_addr,
        }
        if not self.configured or not recipients:
            log.info("SMTP dry-run: would send %s to %s", subject, recipients or "(no recipient)")
            return {"dry_run": True, **payload}

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = from_addr
        message["To"] = ", ".join(recipients)
        message.set_content(body or "")

        client = self._connect()
        try:
            client.send_message(message, from_addr=envelope)
        finally:
            try:
                client.quit()
            except Exception:
                client.close()
        log.info("SMTP sent %s to %s via %s:%s", subject, recipients, self.host, self.port)
        return {"dry_run": False, **payload}
