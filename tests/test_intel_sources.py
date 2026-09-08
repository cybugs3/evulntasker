from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.db.session import Base
from app.models.repository import VulnerabilityRepository
from app.services.intel_sources import (
    enabled_lookups,
    ensure_intel_sources,
    lookup_rows,
    restore_default_intel_sources,
    save_intel_sources,
)


def _sessionmaker():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


def test_ensure_seeds_nvd_and_epss(monkeypatch):
    monkeypatch.setattr("app.api.settings.common.save_env", lambda _updates: None)
    monkeypatch.setenv("INTEL_SOURCES_SEEDED", "false")
    monkeypatch.setenv("NVD_ENABLED", "false")
    monkeypatch.setenv("EPSS_ENABLED", "false")
    get_settings.cache_clear()
    Session = _sessionmaker()
    db = Session()
    ensure_intel_sources(db)
    rows = lookup_rows(db)
    assert {row.name for row in rows} == {"NVD", "FIRST EPSS"}
    assert {row.feed_type for row in rows} == {"nvd", "epss"}
    assert all(not row.enabled for row in rows)
    assert "services.nvd.nist.gov" in lookup_rows(db, "nvd")[0].endpoint
    assert "api.first.org" in lookup_rows(db, "epss")[0].endpoint
    get_settings.cache_clear()


def test_ensure_does_not_resurrect_deleted_sources(monkeypatch):
    monkeypatch.setattr("app.api.settings.common.save_env", lambda _updates: None)
    monkeypatch.setenv("INTEL_SOURCES_SEEDED", "true")
    get_settings.cache_clear()
    Session = _sessionmaker()
    db = Session()
    ensure_intel_sources(db)
    assert lookup_rows(db) == []
    get_settings.cache_clear()


def test_save_can_edit_delete_and_restore(monkeypatch):
    monkeypatch.setattr("app.api.settings.common.save_env", lambda _updates: None)
    Session = _sessionmaker()
    db = Session()
    save_intel_sources(
        db,
        [
            {
                "name": "NVD",
                "feed_type": "nvd",
                "endpoint": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "enabled": False,
            },
            {
                "name": "FIRST EPSS",
                "feed_type": "epss",
                "endpoint": "https://api.first.org/data/v1/epss",
                "enabled": False,
            },
        ],
    )
    nvd = lookup_rows(db, "nvd")[0]
    save_intel_sources(
        db,
        [
            {
                "id": nvd.id,
                "name": "NVD mirror",
                "feed_type": "nvd",
                "endpoint": "https://mirror.example/nvd",
                "enabled": True,
                "api_key": "secret-key",
            }
        ],
    )
    rows = lookup_rows(db)
    assert len(rows) == 1
    assert rows[0].name == "NVD mirror"
    assert rows[0].endpoint == "https://mirror.example/nvd"
    assert rows[0].enabled is True
    assert rows[0].config.get("api_key") == "secret-key"

    restore_default_intel_sources(db)
    types = {row.feed_type for row in lookup_rows(db)}
    assert types == {"nvd", "epss"}
    assert lookup_rows(db, "nvd")[0].endpoint == "https://mirror.example/nvd"
    assert "api.first.org" in lookup_rows(db, "epss")[0].endpoint


def test_disabled_db_row_does_not_lookup(monkeypatch):
    Session = _sessionmaker()
    db = Session()
    db.add(
        VulnerabilityRepository(
            name="NVD",
            feed_type="nvd",
            endpoint="https://nvd.example/cves",
            enabled=False,
            config={"intel_managed": True, "api_key": "k"},
        )
    )
    db.commit()
    monkeypatch.setattr("app.db.session.SessionLocal", Session)
    monkeypatch.setenv("ENRICHMENT_ENABLED", "true")
    monkeypatch.setenv("NVD_ENABLED", "true")
    monkeypatch.setenv("NVD_API_BASE", "https://env.example/nvd")
    get_settings.cache_clear()
    assert enabled_lookups("nvd") == []

    row = lookup_rows(db, "nvd")[0]
    row.enabled = True
    db.commit()
    found = enabled_lookups("nvd")
    assert found == [{"name": "NVD", "endpoint": "https://nvd.example/cves", "api_key": "k"}]
    get_settings.cache_clear()


def test_env_fallback_only_when_type_has_no_row(monkeypatch):
    Session = _sessionmaker()
    monkeypatch.setattr("app.db.session.SessionLocal", Session)
    monkeypatch.setenv("ENRICHMENT_ENABLED", "true")
    monkeypatch.setenv("NVD_ENABLED", "true")
    monkeypatch.setenv("NVD_API_BASE", "https://env.example/nvd")
    monkeypatch.setenv("NVD_API_KEY", "env-key")
    get_settings.cache_clear()
    found = enabled_lookups("nvd")
    assert found == [{"name": "NVD", "endpoint": "https://env.example/nvd", "api_key": "env-key"}]
    get_settings.cache_clear()
