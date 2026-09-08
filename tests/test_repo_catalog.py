from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.db.session import Base
from app.models.repository import VulnerabilityRepository
from app.models.source import InputSource
from app.services.repo_catalog import (
    ensure_atom_feeds,
    purge_placeholder_repos,
    restore_default_atom_feeds,
    sync_atom_repositories,
)


def _session():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)()


def test_purge_removes_internal_scans_placeholder():
    db = _session()
    db.add(
        VulnerabilityRepository(
            name="Internal Scans",
            feed_type="internal",
            endpoint="https://scanner.internal.example/api/findings",
            enabled=True,
            notes="demo",
        )
    )
    db.add(
        VulnerabilityRepository(
            name="NVD",
            feed_type="nvd",
            endpoint="https://services.nvd.nist.gov/rest/json/cves/2.0",
            enabled=False,
        )
    )
    db.commit()
    assert purge_placeholder_repos(db) == 1
    names = {row.name for row in db.query(VulnerabilityRepository).all()}
    assert names == {"NVD"}


def test_atom_feeds_appear_and_disappear_in_catalog():
    db = _session()
    source = InputSource(
        name="ATOM feeds",
        source_type="web_api",
        description="",
        enabled=True,
        config={
            "feeds": [
                {"url": "https://vendor.example/atom.xml", "name": "Vendor ATOM", "token": ""},
                {"url": "https://blog.example/rss.xml", "name": "", "token": ""},
            ]
        },
    )
    db.add(source)
    db.commit()

    sync_atom_repositories(db)
    rows = db.query(VulnerabilityRepository).filter(VulnerabilityRepository.feed_type == "atom").all()
    by_url = {row.endpoint: row.name for row in rows}
    assert by_url["https://vendor.example/atom.xml"] == "Vendor ATOM"
    assert by_url["https://blog.example/rss.xml"] == "blog.example"

    source.config = {"feeds": [{"url": "https://vendor.example/atom.xml", "name": "Vendor ATOM", "token": ""}]}
    db.commit()
    sync_atom_repositories(db)
    rows = db.query(VulnerabilityRepository).filter(VulnerabilityRepository.feed_type == "atom").all()
    assert [row.endpoint for row in rows] == ["https://vendor.example/atom.xml"]


def test_ensure_copies_catalog_into_atom_settings(monkeypatch):
    monkeypatch.setattr("app.api.settings.common.save_env", lambda _updates: None)
    monkeypatch.setenv("ATOM_FEEDS_SEEDED", "false")
    get_settings.cache_clear()
    db = _session()
    source = InputSource(
        name="ATOM feeds",
        source_type="web_api",
        description="",
        enabled=False,
        config={},
    )
    db.add(source)
    db.commit()
    ensure_atom_feeds(db, source=source)
    db.refresh(source)
    urls = [row["url"] for row in (source.config or {}).get("feeds") or []]
    assert urls[:2] == [
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "https://api.first.org/data/v1/epss",
    ]
    assert "https://www.cisa.gov/cybersecurity-advisories/all.xml" in urls
    assert source.enabled is False
    atom_names = {
        row.name
        for row in db.query(VulnerabilityRepository).filter(VulnerabilityRepository.feed_type == "atom")
    }
    assert "CISA Advisories" in atom_names
    assert "Exploit-DB" in atom_names
    assert "NVD" not in atom_names
    get_settings.cache_clear()


def test_ensure_does_not_resurrect_deleted_atom_feeds(monkeypatch):
    monkeypatch.setattr("app.api.settings.common.save_env", lambda _updates: None)
    monkeypatch.setenv("ATOM_FEEDS_SEEDED", "true")
    monkeypatch.setenv("ATOM_LOOKUPS_SEEDED", "true")
    get_settings.cache_clear()
    db = _session()
    source = InputSource(
        name="ATOM feeds",
        source_type="web_api",
        description="",
        enabled=False,
        config={"feeds": []},
    )
    db.add(source)
    db.commit()
    ensure_atom_feeds(db, source=source)
    db.refresh(source)
    assert (source.config or {}).get("feeds") in ([], None)
    assert db.query(VulnerabilityRepository).filter(VulnerabilityRepository.feed_type == "atom").count() == 0
    restore_default_atom_feeds(db)
    db.refresh(source)
    urls = [row["url"] for row in (source.config or {}).get("feeds") or []]
    assert "https://www.cisa.gov/cybersecurity-advisories/all.xml" in urls
    get_settings.cache_clear()


def test_ensure_adds_nvd_and_epss_to_existing_atom_list(monkeypatch):
    monkeypatch.setattr("app.api.settings.common.save_env", lambda _updates: None)
    monkeypatch.setenv("ATOM_FEEDS_SEEDED", "true")
    monkeypatch.setenv("ATOM_LOOKUPS_SEEDED", "false")
    get_settings.cache_clear()
    db = _session()
    source = InputSource(
        name="ATOM feeds",
        source_type="web_api",
        description="",
        enabled=False,
        config={
            "feeds": [
                {"url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "name": "CISA Advisories"}
            ]
        },
    )
    db.add(source)
    db.commit()
    ensure_atom_feeds(db, source=source)
    db.refresh(source)
    urls = [row["url"] for row in (source.config or {}).get("feeds") or []]
    assert urls[0] == "https://services.nvd.nist.gov/rest/json/cves/2.0"
    assert urls[1] == "https://api.first.org/data/v1/epss"
    assert "https://www.cisa.gov/cybersecurity-advisories/all.xml" in urls
    get_settings.cache_clear()


def test_duplicate_exploitdb_rows_are_collapsed():
    db = _session()
    db.add(
        VulnerabilityRepository(
            name="Exploit-DB",
            feed_type="atom",
            endpoint="https://www.exploit-db.com/rss.xml",
            enabled=True,
            config={"atom_managed": True, "url": "https://www.exploit-db.com/rss.xml"},
        )
    )
    db.add(
        VulnerabilityRepository(
            name="Exploit-DB 2",
            feed_type="atom",
            endpoint="https://www.exploit-db.com/rss.xml",
            enabled=True,
            config={"atom_managed": True, "url": "https://www.exploit-db.com/rss.xml"},
        )
    )
    db.commit()
    from app.services.repo_catalog import _dedupe_atom_repos

    assert _dedupe_atom_repos(db) is True
    db.commit()
    rows = db.query(VulnerabilityRepository).filter(VulnerabilityRepository.feed_type == "atom").all()
    assert len(rows) == 1
    assert rows[0].name == "Exploit-DB"
