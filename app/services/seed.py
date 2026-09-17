"""Idempotent first-run seed so a fresh install has a usable dashboard."""

from __future__ import annotations

import logging

from app.db.session import SessionLocal
from app.models.repository import VulnerabilityRepository

log = logging.getLogger(__name__)

REPOS = [
    dict(
        name="NVD",
        feed_type="nvd",
        endpoint="https://services.nvd.nist.gov/rest/json/cves/2.0",
        enabled=False,
        sync_status="idle",
        raw_count=0,
        notes="National Vulnerability Database — source of record for CVE metadata. Enable lookup on this page or under Settings → Feeds → ATOM.",
        config={"intel_managed": True},
    ),
    dict(
        name="FIRST EPSS",
        feed_type="epss",
        endpoint="https://api.first.org/data/v1/epss",
        enabled=False,
        sync_status="idle",
        raw_count=0,
        notes="Exploit Prediction Scoring System probabilities. Enable lookup on this page or under Settings → Feeds → ATOM.",
        config={"intel_managed": True},
    ),
]


def seed_if_empty() -> None:
    db = SessionLocal()
    try:
        from app.api.settings.common import retire_legacy_seed_sources

        try:
            retired = retire_legacy_seed_sources(db)
            if retired:
                log.info("Cleaned %s leftover ingest row(s) / demo source(s)", retired)
        except Exception:
            log.exception("Could not clean leftover ingest rows; continuing startup")
            db.rollback()

        if db.query(VulnerabilityRepository).count() == 0:
            for row in REPOS:
                db.add(VulnerabilityRepository(**row))
            log.info("Seeded %s repositories", len(REPOS))

        db.commit()

        from app.services.intel_sources import ensure_intel_sources

        try:
            ensure_intel_sources(db)
        except Exception:
            log.exception("Could not seed internet intel sources")
            db.rollback()

        from app.services.repo_catalog import ensure_atom_feeds, purge_placeholder_repos

        try:
            removed_repos = purge_placeholder_repos(db)
            if removed_repos:
                log.info("Removed %s placeholder repository row(s)", removed_repos)
            ensure_atom_feeds(db)
        except Exception:
            log.exception("Could not seed ATOM feeds from the repository catalog")
            db.rollback()

        from app.services.inventory_sync import purge_placeholder_assets

        try:
            removed = purge_placeholder_assets(db)
            if removed:
                log.info("Removed %s placeholder Internal systems row(s)", removed)
            db.commit()
        except Exception:
            log.exception("Could not purge placeholder inventory rows")
            db.rollback()
    finally:
        db.close()
