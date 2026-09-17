"""
Microsoft Exchange / Outlook mailbox listener and outbound mailer.

Inbound: poll a folder (default Inbox) for unread messages and turn them
into ingest events. Outbound: notify asset owners and the hunting team.

When Exchange is unconfigured the outbound path logs the message (dry-run)
and inbound polling is a no-op.
"""

from __future__ import annotations

import logging
from typing import Any

from app.config import get_settings

log = logging.getLogger(__name__)


class ExchangeClient:
    def __init__(self, overrides: dict[str, Any] | None = None) -> None:
        self.settings = get_settings()
        self.overrides = overrides or {}

    def _val(self, key: str, env_attr: str, default: str = "") -> str:
        value = (self.overrides.get(key) or "").strip()
        if value:
            return value
        return str(getattr(self.settings, env_attr, default) or default)

    @classmethod
    def from_app(cls) -> "ExchangeClient":
        """Use Feeds → Exchange mailbox credentials when saved, else .env."""
        overrides: dict[str, Any] = {}
        try:
            from app.db.session import SessionLocal
            from app.models.source import InputSource

            db = SessionLocal()
            try:
                source = (
                    db.query(InputSource)
                    .filter(InputSource.source_type == "outlook")
                    .order_by(InputSource.id.asc())
                    .first()
                )
                if source and isinstance(source.config, dict):
                    overrides = dict(source.config)
            finally:
                db.close()
        except Exception:
            log.debug("Could not load Outlook source config for mail", exc_info=True)
        return cls(overrides)

    def configured(self) -> bool:
        return bool(self._val("server", "exchange_server") and self._val("username", "exchange_username"))

    def can_send(self) -> bool:
        password = self.overrides.get("password") or self.settings.exchange_password
        return self.configured() and bool(password)

    def probe(self) -> dict[str, Any]:
        if not self.configured():
            raise ValueError(
                "Save Exchange server and username under Settings → Feeds → Exchange first."
            )
        account = self._connect()
        return {
            "ok": True,
            "provider": "email",
            "mailbox": str(account.primary_smtp_address),
            "server": self._val("server", "exchange_server"),
        }

    def _connect(self):
        from exchangelib import DELEGATE, Account, Configuration, Credentials

        username = self._val("username", "exchange_username")
        domain = (self.overrides.get("domain") or "").strip()
        if domain and "\\" not in username and "@" not in username:
            username = f"{domain}\\{username}"
        creds = Credentials(
            username=username,
            password=self.overrides.get("password") or self.settings.exchange_password,
        )
        config = Configuration(server=self._val("server", "exchange_server"), credentials=creds)
        mailbox = self._val("email", "exchange_email") or username
        return Account(
            primary_smtp_address=mailbox,
            config=config,
            autodiscover=False,
            access_type=DELEGATE,
        )

    def poll_unread(self, limit: int = 25) -> list[dict[str, Any]]:
        """Return unread messages as ingest-ready dicts and mark them read."""
        if not self.configured():
            log.debug("Exchange not configured; skip mailbox poll")
            return []

        account = self._connect()
        folder = account.inbox
        folder_name = self._val("folder", "exchange_folder", "Inbox")
        if folder_name.lower() != "inbox":
            folder = account.root / folder_name

        messages: list[dict[str, Any]] = []
        for item in folder.filter(is_read=False).order_by("-datetime_received")[:limit]:
            body = str(item.text_body or item.body or "")
            messages.append(
                {
                    "subject": str(item.subject or ""),
                    "sender": str(item.sender.email_address if item.sender else ""),
                    "received": str(item.datetime_received),
                    "body": body,
                    "message_id": str(item.message_id or ""),
                    "folder": folder_name or "Inbox",
                }
            )
            item.is_read = True
            item.save(update_fields=["is_read"])
        log.info("Exchange poll collected %s unread message(s)", len(messages))
        return messages

    def send(self, to: list[str], subject: str, body: str) -> dict[str, Any]:
        if not self.can_send():
            log.info("Exchange dry-run mail to %s — %s", to, subject)
            return {"dry_run": True, "to": to, "subject": subject}

        from exchangelib import Message

        account = self._connect()
        message = Message(
            account=account,
            subject=subject,
            body=body,
            to_recipients=to,
        )
        message.send()
        return {"dry_run": False, "to": to, "subject": subject}
