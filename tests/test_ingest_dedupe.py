from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.settings.common import cleanup_input_sources
from app.db.session import Base
from app.models.pipeline import IngestEvent
from app.models.source import InputSource
from app.services.ingestion import (
    _delete_events_by_id,
    ingest_payload,
    purge_duplicate_ingest_events,
    purge_unconfigured_atom_events,
)


def _session():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _source(db, name="ATOM feeds", source_type="web_api", config=None):
    source = InputSource(
        name=name,
        source_type=source_type,
        description="",
        enabled=False,
        config=config or {},
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


def _event(db, source, cve, payload=None, received_at=None):
    event = IngestEvent(
        source_id=source.id,
        payload=payload or {"cve_id": cve},
        raw_text=cve,
        status="done",
        extracted_cves=[cve],
    )
    if received_at is not None:
        event.received_at = received_at
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def test_ingest_payload_skips_already_queued_cve():
    db = _session()
    source = _source(db, name="Local folder", source_type="local")
    first = ingest_payload(db, source, payload={"cve_id": "CVE-2024-3094"})
    second = ingest_payload(db, source, payload={"cve_id": "CVE-2024-3094"})
    assert first is not None
    assert second is None
    assert db.query(IngestEvent).count() == 1


def test_atom_payload_reingests_existing_cve():
    db = _session()
    source = _source(db)
    first = ingest_payload(
        db,
        source,
        payload={
            "cve_id": "CVE-2024-3094",
            "feed_url": "https://vendor.example/atom.xml",
            "title": "old title",
        },
    )
    second = ingest_payload(
        db,
        source,
        payload={
            "cve_id": "CVE-2024-3094",
            "feed_url": "https://vendor.example/atom.xml",
            "title": "updated advisory",
            "summary": "new text",
        },
    )
    assert first is not None
    assert second is not None
    assert first.id != second.id
    assert db.query(IngestEvent).count() == 2
    assert second.payload["_refresh"] is True


def test_purge_drops_atom_rows_when_no_feed_is_configured():
    db = _session()
    source = _source(db)
    leftover = _event(db, source, "CVE-1999-0082", payload={"cve_id": "CVE-1999-0082", "summary": "NVD item"})
    real = _event(
        db,
        source,
        "CVE-2024-3094",
        payload={"cve_id": "CVE-2024-3094", "feed_url": "https://vendor.example/atom.xml"},
    )
    removed = purge_unconfigured_atom_events(db)
    db.commit()
    ids = {row.id for row in db.query(IngestEvent).all()}
    assert leftover.id not in ids
    assert real.id not in ids
    assert removed >= 1


def test_purge_keeps_real_atom_entries_when_feeds_exist():
    db = _session()
    source = _source(
        db,
        config={"feeds": [{"url": "https://vendor.example/atom.xml", "name": "Vendor", "token": ""}]},
    )
    leftover = _event(db, source, "CVE-2024-1111", payload={"cve_id": "CVE-2024-1111"})
    real = _event(
        db,
        source,
        "CVE-2024-3094",
        payload={"cve_id": "CVE-2024-3094", "feed_url": "https://vendor.example/atom.xml"},
    )
    purge_unconfigured_atom_events(db)
    db.commit()
    ids = {row.id for row in db.query(IngestEvent).all()}
    assert leftover.id not in ids
    assert real.id in ids


def test_purge_duplicate_keeps_newest_row_per_cve():
    db = _session()
    source = _source(db, name="Local folder", source_type="local")
    now = datetime.now(timezone.utc)
    older = _event(db, source, "CVE-2024-3094", received_at=now - timedelta(minutes=5))
    newer = _event(db, source, "CVE-2024-3094", received_at=now)
    removed = purge_duplicate_ingest_events(db)
    db.commit()
    ids = {row.id for row in db.query(IngestEvent).all()}
    assert removed == 1
    assert older.id not in ids
    assert newer.id in ids


def test_cleanup_deletes_legacy_nvd_source_instead_of_relabeling_as_atom():
    db = _session()
    leftover = _source(db, name="NVD API Feed", source_type="api_feed")
    event = _event(db, leftover, "CVE-1999-0082")
    atom = _source(db)
    cleanup_input_sources(db)
    db.commit()
    types = {row.source_type for row in db.query(InputSource).all()}
    assert "api_feed" not in types
    assert db.get(IngestEvent, event.id) is None
    assert db.get(InputSource, leftover.id) is None
    assert db.get(InputSource, atom.id) is not None
    assert db.query(IngestEvent).filter(IngestEvent.source_id == atom.id).count() == 0


def test_delete_events_by_id_chunks_large_lists():
    db = _session()
    source = _source(db, name="Local folder", source_type="local")
    events = [_event(db, source, f"CVE-2024-{i:04d}") for i in range(1, 8)]
    removed = _delete_events_by_id(db, [event.id for event in events], chunk_size=2)
    db.commit()
    assert removed == 7
    assert db.query(IngestEvent).count() == 0
