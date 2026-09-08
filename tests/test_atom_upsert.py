from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.pipeline import IngestEvent
from app.models.source import InputSource
from app.pipeline.step1_ingest import accept_cve
from app.workers.scheduler import _is_due, _poll_interval


def _session():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _source(db, config=None):
    source = InputSource(
        name="ATOM feeds",
        source_type="web_api",
        description="",
        enabled=True,
        config=config or {"feeds": [{"url": "https://vendor.example/atom.xml"}]},
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


def _event(db, source, payload):
    event = IngestEvent(
        source_id=source.id,
        payload=payload,
        raw_text=payload.get("cve_id") or "",
        status="queued",
        extracted_cves=[payload["cve_id"]],
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def test_accept_cve_updates_existing_atom_row():
    db = _session()
    source = _source(db)
    first = _event(
        db,
        source,
        {
            "cve_id": "CVE-2024-3094",
            "feed_url": "https://vendor.example/atom.xml",
            "title": "old title",
            "summary": "old summary",
        },
    )
    vuln, created = accept_cve(db, first, source, "CVE-2024-3094", summary="old summary")
    assert created == "created"
    assert vuln.title == "old title"

    second = _event(
        db,
        source,
        {
            "cve_id": "CVE-2024-3094",
            "feed_url": "https://vendor.example/atom.xml",
            "title": "updated advisory",
            "summary": "new text",
            "link": "https://vendor.example/cve-2024-3094",
        },
    )
    skipped, outcome = accept_cve(db, second, source, "CVE-2024-3094", summary="new text")
    assert outcome == "skipped"
    assert skipped.title == "old title"

    updated, outcome = accept_cve(
        db, second, source, "CVE-2024-3094", summary="new text", refresh=True
    )
    assert outcome == "updated"
    assert updated.id == vuln.id
    assert updated.title == "updated advisory"
    assert updated.description == "new text"
    assert updated.enrichment.get("feed_link") == "https://vendor.example/cve-2024-3094"


def test_atom_poll_interval_honors_last_poll():
    source = SimpleNamespace(config={"poll_seconds": 3600})
    assert _poll_interval(source, "web_api") == 3600
    assert _is_due(source, "web_api") is True

    source.config["last_poll_at"] = datetime.now(timezone.utc).isoformat()
    assert _is_due(source, "web_api") is False

    source.config["last_poll_at"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    assert _is_due(source, "web_api") is True


def test_atom_poll_defaults_to_one_hour():
    source = SimpleNamespace(config={})
    assert _poll_interval(source, "web_api") == 3600
