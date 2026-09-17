"""Sanitize catalog emails and versions before SMTP or matching."""

from __future__ import annotations

import re
from typing import Any

_BIDI_RE = re.compile(r"[\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
_ZW_RE = re.compile(r"[\u200b\u200c\u200d\u2060]")
_FLOAT_VER_RE = re.compile(r"^\d+\.\d+$")
_PLACEHOLDER_MAIL = {"soc@example.com", "threat-hunting@example.com"}


def clean_email(value: Any) -> str:
    """Strip bidi/zero-width marks so SMTP AUTH/RCPT stay RFC 5321."""
    text = _BIDI_RE.sub("", str(value or ""))
    text = _ZW_RE.sub("", text)
    email = " ".join(text.split()).strip()
    if not email or email.lower() in _PLACEHOLDER_MAIL:
        return ""
    if "@" not in email or " " in email:
        return ""
    return email


def parse_email_domains(raw: Any) -> list[str]:
    """Comma/space separated domains. Empty means allow every recipient."""
    text = str(raw or "")
    out: list[str] = []
    seen: set[str] = set()
    for part in text.replace(";", ",").replace(" ", ",").split(","):
        domain = part.strip().lower().lstrip("@")
        if not domain or domain in seen or "." not in domain:
            continue
        seen.add(domain)
        out.append(domain)
    return out


def email_domain_allowed(email: str, domains: list[str] | None) -> bool:
    if not domains:
        return True
    cleaned = clean_email(email)
    if not cleaned or "@" not in cleaned:
        return False
    host = cleaned.rsplit("@", 1)[-1].lower()
    return any(host == domain or host.endswith("." + domain) for domain in domains)


def sanitize_version(value: Any) -> str:
    """Collapse Excel/IEEE float noise (24.039999999999999 → 24.04)."""
    text = str(value or "").strip()
    if not text:
        return ""
    if _FLOAT_VER_RE.fullmatch(text) and len(text) >= 12:
        try:
            rounded = f"{float(text):.4f}".rstrip("0").rstrip(".")
            return rounded or text
        except ValueError:
            return text
    return text
