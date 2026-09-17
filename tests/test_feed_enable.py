from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.repository import VulnerabilityRepository
from app.models.source import InputSource
from app.services.repo_catalog import (
    atom_feed_enabled,
    sync_atom_channel_enabled,
    sync_atom_repositories,
)


def _session():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)()


def test_save_local_does_not_change_enabled():
    from app.api.settings.feeds import LocalIn, save_local

    db = _session()
    db.add(
        InputSource(
            name="Local folder",
            source_type="local",
            description="",
            enabled=True,
            config={"path": "/tmp/old", "poll_seconds": 60},
        )
    )
    db.commit()
    save_local(LocalIn(enabled=False, name="Local folder", path="/tmp/inbox", poll_seconds=90), db)
    source = db.query(InputSource).filter(InputSource.source_type == "local").one()
    assert source.enabled is True
    assert source.config["path"] == "/tmp/inbox"
    assert int(source.config["poll_seconds"]) == 90


def test_align_legacy_pauses_atom_rows_when_channel_was_off():
    db = _session()
    url = "https://vendor.example/atom.xml"
    source = InputSource(
        name="ATOM feeds",
        source_type="web_api",
        description="",
        enabled=False,
        config={"feeds": [{"url": url, "name": "Vendor ATOM"}]},
    )
    db.add(source)
    db.add(
        VulnerabilityRepository(
            name="Vendor ATOM",
            feed_type="atom",
            endpoint=url,
            enabled=True,
            config={"atom_managed": True, "url": url},
        )
    )
    db.commit()
    sync_atom_channel_enabled(db, align_legacy=True)
    row = db.query(VulnerabilityRepository).filter(VulnerabilityRepository.feed_type == "atom").one()
    assert row.enabled is False
    assert source.enabled is False


def test_enabling_one_atom_feed_turns_channel_on():
    db = _session()
    url = "https://vendor.example/atom.xml"
    source = InputSource(
        name="ATOM feeds",
        source_type="web_api",
        description="",
        enabled=False,
        config={"feeds": [{"url": url, "name": "Vendor ATOM"}]},
    )
    db.add(source)
    row = VulnerabilityRepository(
        name="Vendor ATOM",
        feed_type="atom",
        endpoint=url,
        enabled=False,
        config={"atom_managed": True, "url": url},
    )
    db.add(row)
    db.commit()
    row.enabled = True
    sync_atom_channel_enabled(db)
    assert source.enabled is True
    assert atom_feed_enabled(db, url) is True


def test_new_atom_url_starts_paused():
    db = _session()
    source = InputSource(
        name="ATOM feeds",
        source_type="web_api",
        description="",
        enabled=False,
        config={"feeds": [{"url": "https://vendor.example/atom.xml", "name": "Vendor ATOM"}]},
    )
    db.add(source)
    db.commit()
    sync_atom_repositories(db)
    row = db.query(VulnerabilityRepository).filter(VulnerabilityRepository.feed_type == "atom").one()
    assert row.enabled is False


def test_pull_skips_paused_atom_unless_manual_url(monkeypatch):
    from app.api.settings.feeds import pull_web_api

    db = _session()
    url = "https://vendor.example/atom.xml"
    source = InputSource(
        name="ATOM feeds",
        source_type="web_api",
        description="",
        enabled=False,
        config={"feeds": [{"url": url, "name": "Vendor ATOM", "feed_type": "atom"}]},
    )
    db.add(source)
    db.add(
        VulnerabilityRepository(
            name="Vendor ATOM",
            feed_type="atom",
            endpoint=url,
            enabled=False,
            config={"atom_managed": True, "url": url},
        )
    )
    db.commit()
    called: list[str] = []

    def fake_get(target, **_kwargs):
        called.append(target)
        return SimpleNamespace(text="<feed xmlns='http://www.w3.org/2005/Atom'></feed>", raise_for_status=lambda: None)

    monkeypatch.setattr("app.api.settings.feeds.httpx.get", fake_get)
    monkeypatch.setattr("app.api.settings.feeds.ingest_payload", lambda *_args, **_kwargs: False)
    assert pull_web_api(db, source) == 0
    assert called == []
    assert pull_web_api(db, source, only_url=url) == 0
    assert called == [url]
