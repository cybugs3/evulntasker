"""Vendor/product identity: drop NVD placeholders and recover names from advisory text."""

from __future__ import annotations

import re
from typing import Any

_PLACEHOLDERS = frozenset(
    {
        "n/a",
        "n.a.",
        "n.a",
        "na",
        "n/a.",
        "unknown",
        "none",
        "null",
        "-",
        "--",
        "*",
        "unspecified",
        "not applicable",
        "not available",
        "tbd",
    }
)
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_CUT = re.compile(
    r"\s+(?:"
    r"before|through|prior to|up to(?: and including)?|until|since|"
    r"versions?|allows?|does|did|is\b|are\b|was\b|were\b|has\b|have\b|had\b|"
    r"suffers|contains|via\b|in \d|for \d"
    r")\b",
    re.I,
)
_LEAD = re.compile(r"^(?:a|an|the|this|there is|there was)\s+", re.I)
_VERSION = re.compile(r"\b\d+(?:\.\d+)+\b")
_STOP = frozenset({"vulnerability", "issue", "flaw", "bug", "cve"})


def clean_identity(value: Any) -> str:
    """Return a usable vendor/product/version, or empty for NVD placeholders."""
    text = " ".join(str(value or "").replace("_", " ").split()).strip()
    if not text or text.lower() in _PLACEHOLDERS:
        return ""
    return text


def derive_identity(title: str | None, description: str | None = None) -> tuple[str, str]:
    """Best-effort vendor + product from an advisory headline when CPE is missing."""
    for raw in (title, description):
        line = " ".join(str(raw or "").split())
        if not line:
            continue
        line = line.split("\n", 1)[0]
        line = line.split(". ", 1)[0]
        line = _LEAD.sub("", line)
        phrase = _CUT.split(line, maxsplit=1)[0]
        phrase = _VERSION.sub(" ", phrase)
        phrase = " ".join(phrase.replace("_", " ").split()).strip(" ,;:-")
        tokens = _TOKEN_RE.findall(phrase.lower())
        while tokens and tokens[-1] in _STOP:
            tokens.pop()
        if len(tokens) < 2:
            continue
        words = phrase.split()
        vendor = words[0]
        product = " ".join(words[1:]).strip()
        if not product:
            continue
        return vendor, product
    return "", ""


def identity_for(vuln: Any) -> tuple[str, str]:
    vendor = clean_identity(getattr(vuln, "vendor", None))
    product = clean_identity(getattr(vuln, "product", None))
    if vendor and product:
        return vendor, product
    derived_vendor, derived_product = derive_identity(
        getattr(vuln, "title", None),
        getattr(vuln, "description", None),
    )
    return vendor or derived_vendor, product or derived_product


def ensure_identity(vuln: Any) -> bool:
    """Clear placeholders and fill vendor/product from the advisory when missing."""
    changed = False
    vendor = clean_identity(getattr(vuln, "vendor", None))
    product = clean_identity(getattr(vuln, "product", None))
    versions = clean_identity(getattr(vuln, "affected_versions", None))
    if (getattr(vuln, "vendor", None) or "") != vendor:
        vuln.vendor = vendor
        changed = True
    if (getattr(vuln, "product", None) or "") != product:
        vuln.product = product
        changed = True
    if hasattr(vuln, "affected_versions") and (vuln.affected_versions or "") != versions:
        vuln.affected_versions = versions
        changed = True
    if vendor and product:
        return changed
    derived_vendor, derived_product = derive_identity(
        getattr(vuln, "title", None),
        getattr(vuln, "description", None),
    )
    if not vendor and derived_vendor:
        vuln.vendor = derived_vendor
        changed = True
    if not product and derived_product:
        vuln.product = derived_product
        changed = True
    return changed
