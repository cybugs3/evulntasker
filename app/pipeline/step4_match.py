"""
Step 4 — match enriched vendor/product/version against the local asset catalog.

Remote CMDB / Sonatype / ITNM systems are *not* part of this step.
They teach the Internal systems catalog on a schedule (new equipment only).
This step only queries that local table so CVE matching stays fast.

Matching is not a raw string-equal of NVD CPE to the inventory row.
A Linux kernel CVE must hit Red Hat / Ubuntu / etc. even when the catalog
vendor is "REDHAT" and product type is "linux".
"""

from __future__ import annotations

import logging
import re

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.integrations.ai_copilot import AICopilot
from app.models.asset import Asset, AssetMatch
from app.models.enums import PipelineStatus
from app.models.vulnerability import Vulnerability
from app.pipeline.state import begin_step, complete_step, log_ai_fallback
from app.utils.identity import clean_identity, identity_for, ensure_identity

log = logging.getLogger(__name__)

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_FAMILY_RE = re.compile(r"\b(\d+)\s*\.\s*(x|\d+)\b", re.I)
_LEAD_VER_RE = re.compile(r"(\d+)(?:\.(\d+))?")
# Shared alone, these words match too many unrelated products (Policy Secure vs Connect Secure).
_GENERIC_PRODUCT_TOKENS = frozenset(
    {
        "appliance",
        "central",
        "client",
        "cloud",
        "core",
        "data",
        "edition",
        "endpoint",
        "enterprise",
        "firewall",
        "gateway",
        "http",
        "manager",
        "management",
        "network",
        "next",
        "os",
        "platform",
        "plus",
        "secure",
        "security",
        "server",
        "service",
        "software",
        "ssl",
        "suite",
        "system",
        "virtual",
        "vpn",
        "web",
    }
)

# Distro names that run the Linux kernel. "oracle" / "amazon" are not listed
# as vendor-only hits so Oracle Database or AWS apps are not treated as OSes.
LINUX_VENDORS = frozenset(
    {
        "linux",
        "redhat",
        "red hat",
        "rhel",
        "centos",
        "fedora",
        "ubuntu",
        "debian",
        "suse",
        "opensuse",
        "alma",
        "almalinux",
        "rocky",
        "gnu",
    }
)
LINUX_PRODUCTS = frozenset(
    {
        "linux",
        "linux kernel",
        "kernel",
        "gnu linux",
        "red hat enterprise linux",
        "rhel",
        "centos",
        "fedora",
        "ubuntu",
        "debian",
        "suse",
        "oracle linux",
        "amazon linux",
        "almalinux",
        "rocky linux",
    }
)
LINUX_TYPES = frozenset(
    {
        "linux",
        "os",
        "operating system",
        "operating-system",
        "operating_system",
        "unix",
        "server os",
        "server-os",
    }
)
LINUX_HINTS = (
    "linux",
    "rhel",
    "redhat",
    "red hat",
    "centos",
    "ubuntu",
    "debian",
    "fedora",
    "kernel",
)


def _norm(value: str | None) -> str:
    return (value or "").strip().lower()


def _tokens(value: str | None) -> set[str]:
    return set(_TOKEN_RE.findall(_norm(value)))


def _blob(*parts: str | None) -> str:
    return " ".join(_norm(part) for part in parts if part)


def _text_overlap(left: str, right: str) -> bool:
    if not left or not right:
        return False
    return left in right or right in left


def _token_overlap(left: str, right: str) -> bool:
    return bool(_tokens(left) & _tokens(right))


def _product_overlap(asset_product: str, cve_product: str) -> bool:
    """Require a real product name, not a single generic token such as `secure`."""
    if _text_overlap(asset_product, cve_product):
        return True
    shared = _tokens(asset_product) & _tokens(cve_product)
    return any(len(token) >= 5 and token not in _GENERIC_PRODUCT_TOKENS for token in shared)


def _has_identity(vuln: Vulnerability) -> bool:
    """A CVE can only match inventory when vendor and/or product is known."""
    vendor, product = identity_for(vuln)
    return bool(vendor or product)


def is_linux_cve(vuln: Vulnerability) -> bool:
    vendor, product = identity_for(vuln)
    vendor, product, ptype = _norm(vendor), _norm(product), _norm(vuln.product_type)
    if not vendor and not product:
        return False
    hay = _blob(vendor, product, ptype)
    if vendor in LINUX_VENDORS or product in LINUX_PRODUCTS or ptype in LINUX_TYPES:
        return True
    if "kernel" in product and (vendor == "linux" or "linux" in product):
        return True
    return "linux kernel" in hay


def is_linux_asset(asset: Asset) -> bool:
    vendor, product, stype = _norm(asset.vendor), _norm(asset.product), _norm(asset.system_type)
    hay = _blob(vendor, product, stype)
    if stype in LINUX_TYPES:
        return True
    if vendor in LINUX_VENDORS:
        return True
    if product in LINUX_PRODUCTS:
        return True
    return any(hint in hay for hint in LINUX_HINTS)


def _direct_hit(asset: Asset, vuln: Vulnerability) -> bool:
    v_vendor, v_product = (_norm(part) for part in identity_for(vuln))
    a_vendor, a_product = _norm(asset.vendor), _norm(asset.product)
    if not v_vendor and not v_product:
        return False
    vendor_ok = bool(v_vendor) and (
        _text_overlap(a_vendor, v_vendor) or _token_overlap(a_vendor, v_vendor)
    )
    product_ok = bool(v_product) and _product_overlap(a_product, v_product)
    if v_vendor and v_product:
        return vendor_ok and product_ok
    return vendor_ok or product_ok


def _version_field_hay(vuln: Vulnerability) -> str:
    return " ".join(
        part
        for part in (
            clean_identity(getattr(vuln, "affected_versions", None)),
            clean_identity(getattr(vuln, "version", None)),
        )
        if part
    ).lower()


def _advisory_text(vuln: Vulnerability) -> str:
    title = clean_identity(getattr(vuln, "title", None)) or ""
    description = clean_identity(getattr(vuln, "description", None)) or ""
    if description:
        description = description[:500]
    return f"{title} {description}".strip().lower()


def _lead_major_minor(asset_ver: str) -> tuple[int | None, int | None]:
    match = _LEAD_VER_RE.search(asset_ver)
    if not match:
        return None, None
    major = int(match.group(1))
    minor = int(match.group(2)) if match.group(2) is not None else None
    return major, minor


def _plausible_major(major: int) -> bool:
    return not (1900 <= major <= 2099)


def _families_cover(asset_ver: str, text: str) -> bool:
    """`22.x` covers 22.7R2.4; `9.0` does not cover 22.x or a different 9.1 minor."""
    if not text:
        return False
    a_major, a_minor = _lead_major_minor(asset_ver)
    if a_major is None or not _plausible_major(a_major):
        return False
    for match in _FAMILY_RE.finditer(text):
        major = int(match.group(1))
        if not _plausible_major(major):
            continue
        rest = match.group(2).lower()
        if rest == "x":
            if a_major == major:
                return True
            continue
        minor = int(rest)
        head = f"{major}.{minor}"
        if asset_ver.startswith(head):
            return True
        if a_major == major and a_minor == minor:
            return True
    return False


def version_overlap(asset_version: str | None, vuln: Vulnerability) -> tuple[bool, float]:
    """Return (keep, confidence bump). Empty versions do not block a vendor/product hit."""
    asset_ver = _norm(asset_version)
    hay = _version_field_hay(vuln)
    advisory = _advisory_text(vuln)
    if not asset_ver or not hay:
        return True, 0.0
    if asset_ver in hay or hay in asset_ver:
        return True, 0.1
    # NVD `affected` often stores prose ("All versions below 5.10 SP1") rather than a CPE version.
    # That is not comparable, so it must not exclude a vendor/product hit.
    prose_markers = (
        "below",
        "prior to",
        "all version",
        "earlier",
        "before ",
        "service pack",
    )
    if any(marker in hay for marker in prose_markers):
        parts = asset_ver.split(".")
        if len(parts) >= 2 and ".".join(parts[:2]) in hay:
            return True, 0.05
        return True, 0.0
    # Prefix match on the structured version field only (not the advisory sentence).
    if hay.startswith(asset_ver) or asset_ver.startswith(hay.split()[0] if hay else ""):
        short = hay.split(",")[0].split()[0]
        if short and (asset_ver.startswith(short) or short.startswith(asset_ver)):
            return True, 0.05
    if _families_cover(asset_ver, hay) or _families_cover(asset_ver, advisory):
        return True, 0.05
    return False, 0.0


def match_local_assets(db: Session, vuln: Vulnerability) -> list[tuple[Asset, float]]:
    assets = db.query(Asset).filter(Asset.active.is_(True)).all()
    linux_cve = is_linux_cve(vuln)
    hits: list[tuple[Asset, float]] = []
    for asset in assets:
        family = linux_cve and is_linux_asset(asset)
        direct = _direct_hit(asset, vuln)
        if not family and not direct:
            continue
        bump = 0.0
        if direct:
            keep, bump = version_overlap(asset.version, vuln)
            if not keep and not family:
                continue
            if not keep:
                bump = 0.0
        confidence = min(0.99, (0.92 if direct else 0.86) + bump)
        hits.append((asset, confidence))
    return hits


def _sync_matches(db: Session, vuln: Vulnerability, matched: list[tuple[Asset, float]]) -> None:
    keep_ids = {asset.id for asset, _ in matched}
    stale = (
        db.query(AssetMatch)
        .filter(AssetMatch.vulnerability_id == vuln.id)
        .all()
    )
    for row in stale:
        if row.asset_id not in keep_ids:
            db.delete(row)
    for asset, confidence in matched:
        method = asset.source if asset.source in {"csv", "cmdb", "sonatype", "itnm", "local"} else "local"
        _upsert_match(db, vuln, asset, method, confidence)
    db.flush()
    db.expire(vuln, ["matches"])


def _upsert_match(db: Session, vuln: Vulnerability, asset: Asset, method: str, confidence: float) -> None:
    existing = (
        db.query(AssetMatch)
        .filter(AssetMatch.vulnerability_id == vuln.id, AssetMatch.asset_id == asset.id)
        .one_or_none()
    )
    if existing:
        existing.confidence = max(existing.confidence, confidence)
        existing.method = method
        return
    db.add(
        AssetMatch(
            vulnerability_id=vuln.id,
            asset_id=asset.id,
            method=method,
            confidence=confidence,
        )
    )


def _inventory_count(db: Session) -> int:
    return db.query(func.count(Asset.id)).filter(Asset.active.is_(True)).scalar() or 0


async def match_assets(db: Session, vuln: Vulnerability, ai_fallback: bool = True) -> list[AssetMatch]:
    begin_step(db, vuln, PipelineStatus.MATCHED, f"Asset matching started for {vuln.cve_id}")
    inventory_size = _inventory_count(db)
    ensure_identity(vuln)

    if inventory_size == 0:
        complete_step(
            db,
            vuln,
            PipelineStatus.MATCHED,
            "Local inventory is empty — add systems by hand or import a CSV before matching",
            {"count": 0, "inventory_empty": True},
        )
        return []

    if not _has_identity(vuln):
        _sync_matches(db, vuln, [])
        complete_step(
            db,
            vuln,
            PipelineStatus.MATCHED,
            "No vendor/product on the CVE — matching skipped until enrichment fills identity",
            {"count": 0, "skipped": True, "reason": "missing_identity", "inventory_size": inventory_size},
        )
        return []

    matched = match_local_assets(db, vuln)
    linux_cve = is_linux_cve(vuln)
    methods: list[str] = []
    reasons: list[str] = []
    _sync_matches(db, vuln, matched)
    for asset, _confidence in matched:
        methods.append(asset.source or "local")
        if linux_cve and is_linux_asset(asset):
            reasons.append("linux-os-family")
        else:
            reasons.append("vendor-product")

    if matched:
        complete_step(
            db,
            vuln,
            PipelineStatus.MATCHED,
            f"Matched {len(matched)} local asset(s) for {vuln.cve_id}",
            {
                "count": len(matched),
                "methods": sorted(set(methods)),
                "reasons": sorted(set(reasons)),
                "inventory_size": inventory_size,
            },
        )
        return list(vuln.matches)

    if not ai_fallback or not AICopilot().available:
        complete_step(
            db,
            vuln,
            PipelineStatus.MATCHED,
            "No local inventory match and AI fallback disabled",
            {"count": 0, "inventory_size": inventory_size, "ai_skipped": True},
        )
        return []

    log.info("%s no local inventory hit — AI ownership fallback (no fake asset created)", vuln.cve_id)
    snapshot = [
        {
            "name": a.name,
            "vendor": a.vendor,
            "product": a.product,
            "team": a.team,
            "owner_email": a.owner_email,
        }
        for a in db.query(Asset).filter(Asset.active.is_(True)).limit(80).all()
    ]
    ai = await AICopilot().infer_ownership(vuln.vendor, vuln.product, snapshot)
    vuln.ai_matching_used = True
    enrichment = dict(vuln.enrichment or {}) if isinstance(vuln.enrichment, dict) else {}
    enrichment["inferred_owner"] = ai
    vuln.enrichment = enrichment
    log_ai_fallback(
        db,
        vuln,
        "AI inferred an owner. Internal systems were not changed.",
        {"reasoning": ai, "inventory_size": inventory_size},
    )
    complete_step(
        db,
        vuln,
        PipelineStatus.MATCHED,
        "No local inventory match — AI inferred ownership without adding a catalog row",
        {"count": 0, "method": "ai", "reasoning": ai, "inventory_size": inventory_size},
    )
    return list(vuln.matches)


# Kept for debug_trace imports
def _local_matches(db: Session, vendor: str | None, product: str | None) -> list[Asset]:
    q = db.query(Asset).filter(Asset.active.is_(True))
    if vendor:
        q = q.filter(func.lower(Asset.vendor).like(f"%{_norm(vendor)}%"))
    if product:
        q = q.filter(func.lower(Asset.product).like(f"%{_norm(product)}%"))
    return q.all()
