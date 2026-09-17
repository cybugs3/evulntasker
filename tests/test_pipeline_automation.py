import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.pipeline import IngestEvent
from app.models.source import InputSource
from app.models.vulnerability import Vulnerability
from app.pipeline.orchestrator import PipelineOrchestrator
from app.pipeline.step2_extract import ExtractionResult
from app.workers.queue import InProcessQueue


def _session():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _source(db, name="Local folder"):
    source = InputSource(name=name, source_type="local", enabled=True, config={})
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


def _event(db, source, cve="CVE-2024-4844", payload=None):
    payload = payload or {"cve_id": cve}
    event = IngestEvent(
        source_id=source.id,
        payload=payload,
        raw_text=cve,
        status="queued",
        extracted_cves=[cve],
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def _extract(cve="CVE-2024-4844"):
    async def fake_extract(event, ai_fallback=True):
        return ExtractionResult(cve_ids=[cve], per_cve={cve: {}})

    return fake_extract


def test_new_cve_runs_enrich_match_act(monkeypatch):
    db = _session()
    source = _source(db)
    event = _event(db, source)
    calls = []

    async def fake_ema(self, run, vuln, ai_fallback=True, source_fields=None):
        calls.append(("ema", vuln.cve_id))

    monkeypatch.setattr("app.pipeline.orchestrator.extract_from_event", _extract())
    monkeypatch.setattr(PipelineOrchestrator, "_enrich_match_act", fake_ema)
    monkeypatch.setattr("app.pipeline.orchestrator.get_settings", lambda: SimpleNamespace(ai_enabled=False))
    monkeypatch.setattr("app.pipeline.orchestrator.finalize_extract", AsyncMock())

    asyncio.run(PipelineOrchestrator(db).run_event(event.id))
    assert calls == [("ema", "CVE-2024-4844")]
    assert db.query(Vulnerability).filter_by(cve_id="CVE-2024-4844").one_or_none() is not None


def test_inline_cve_runs_full_pipeline(monkeypatch):
    db = _session()
    from app.services.ingestion import ingest_inline_cve

    event = ingest_inline_cve(db, cve_id="CVE-2024-4844")
    calls = []

    async def fake_ema(self, run, vuln, ai_fallback=True, source_fields=None):
        calls.append(("ema", vuln.cve_id))

    monkeypatch.setattr("app.pipeline.orchestrator.extract_from_event", _extract())
    monkeypatch.setattr(PipelineOrchestrator, "_enrich_match_act", fake_ema)
    monkeypatch.setattr("app.pipeline.orchestrator.get_settings", lambda: SimpleNamespace(ai_enabled=False))
    monkeypatch.setattr("app.pipeline.orchestrator.finalize_extract", AsyncMock())

    asyncio.run(PipelineOrchestrator(db).run_event(event.id))
    vuln = db.query(Vulnerability).filter_by(cve_id="CVE-2024-4844").one()
    assert calls == [("ema", "CVE-2024-4844")]
    assert vuln.source_name == "Inline CVE"


def test_known_cve_does_not_start_pipeline(monkeypatch):
    db = _session()
    source = _source(db)
    db.add(Vulnerability(cve_id="CVE-2024-4844", title="already there"))
    db.commit()
    event = _event(db, source)
    calls = []

    async def fake_ema(self, run, vuln, ai_fallback=True, source_fields=None):
        calls.append(vuln.cve_id)

    monkeypatch.setattr("app.pipeline.orchestrator.extract_from_event", _extract())
    monkeypatch.setattr(PipelineOrchestrator, "_enrich_match_act", fake_ema)
    monkeypatch.setattr("app.pipeline.orchestrator.get_settings", lambda: SimpleNamespace(ai_enabled=False))

    asyncio.run(PipelineOrchestrator(db).run_event(event.id))
    assert calls == []


def test_updated_feed_cve_runs_full_pipeline(monkeypatch):
    db = _session()
    source = _source(db, name="ATOM feeds")
    db.add(Vulnerability(cve_id="CVE-2024-4844", title="old"))
    db.commit()
    event = _event(
        db,
        source,
        payload={
            "cve_id": "CVE-2024-4844",
            "feed_url": "https://vendor.example/atom.xml",
            "title": "updated advisory",
        },
    )
    calls = []

    async def fake_ema(self, run, vuln, ai_fallback=True, source_fields=None):
        calls.append(vuln.cve_id)

    monkeypatch.setattr("app.pipeline.orchestrator.extract_from_event", _extract())
    monkeypatch.setattr(PipelineOrchestrator, "_enrich_match_act", fake_ema)
    monkeypatch.setattr("app.pipeline.orchestrator.get_settings", lambda: SimpleNamespace(ai_enabled=False))
    monkeypatch.setattr("app.pipeline.orchestrator.finalize_extract", AsyncMock())

    asyncio.run(PipelineOrchestrator(db).run_event(event.id))
    assert calls == ["CVE-2024-4844"]


def test_operator_rerun_runs_full_pipeline(monkeypatch):
    db = _session()
    from app.services.ingestion import queue_cve_rerun

    db.add(Vulnerability(cve_id="CVE-2024-4844", title="already there"))
    db.commit()
    event = queue_cve_rerun(db, "CVE-2024-4844")
    calls = []

    async def fake_ema(self, run, vuln, ai_fallback=True, source_fields=None):
        calls.append(vuln.cve_id)

    monkeypatch.setattr("app.pipeline.orchestrator.extract_from_event", _extract())
    monkeypatch.setattr(PipelineOrchestrator, "_enrich_match_act", fake_ema)
    monkeypatch.setattr("app.pipeline.orchestrator.get_settings", lambda: SimpleNamespace(ai_enabled=False))
    monkeypatch.setattr("app.pipeline.orchestrator.finalize_extract", AsyncMock())

    asyncio.run(PipelineOrchestrator(db).run_event(event.id))
    assert calls == ["CVE-2024-4844"]


def test_incomplete_enrichment_does_not_match_or_act(monkeypatch):
    db = _session()
    source = _source(db)
    event = _event(db, source)
    matched = []
    acted = []

    async def fake_enrich(db, vuln, ai_fallback=True, source_fields=None):
        vuln.enrichment = {"waiting": True, "missing": ["vendor", "product", "cvss"]}
        vuln.pipeline_status = "waiting_enrichment"
        return vuln

    async def fake_match(db, vuln, ai_fallback=True):
        matched.append(vuln.cve_id)

    async def fake_act(db, vuln, audit=True, store=True):
        acted.append(vuln.cve_id)

    monkeypatch.setattr("app.pipeline.orchestrator.extract_from_event", _extract())
    monkeypatch.setattr("app.pipeline.orchestrator.enrich_cve", fake_enrich)
    monkeypatch.setattr("app.pipeline.orchestrator.match_assets", fake_match)
    monkeypatch.setattr("app.pipeline.orchestrator.take_action", fake_act)
    monkeypatch.setattr(
        "app.pipeline.orchestrator.get_settings",
        lambda: SimpleNamespace(ai_enabled=False, enrichment_enabled=True),
    )
    monkeypatch.setattr("app.pipeline.orchestrator.finalize_extract", AsyncMock())

    asyncio.run(PipelineOrchestrator(db).run_event(event.id))
    assert matched == []
    assert acted == []
    vuln = db.query(Vulnerability).filter_by(cve_id="CVE-2024-4844").one()
    assert vuln.pipeline_status == "waiting_enrichment"


def test_unmatched_cve_does_not_run_actions(monkeypatch):
    db = _session()
    source = _source(db)
    event = _event(db, source, cve="CVE-2022-0121")
    matched = []
    acted = []

    async def fake_enrich(db, vuln, ai_fallback=True, source_fields=None):
        return vuln

    async def fake_match(db, vuln, ai_fallback=True):
        matched.append(vuln.cve_id)
        return []

    async def fake_act(db, vuln, audit=True, store=True):
        acted.append(vuln.cve_id)

    monkeypatch.setattr("app.pipeline.orchestrator.extract_from_event", _extract("CVE-2022-0121"))
    monkeypatch.setattr("app.pipeline.orchestrator.enrich_cve", fake_enrich)
    monkeypatch.setattr("app.pipeline.orchestrator.match_assets", fake_match)
    monkeypatch.setattr("app.pipeline.orchestrator.take_action", fake_act)
    monkeypatch.setattr(
        "app.pipeline.orchestrator.get_settings",
        lambda: SimpleNamespace(ai_enabled=False, enrichment_enabled=True),
    )
    monkeypatch.setattr("app.pipeline.orchestrator.finalize_extract", AsyncMock())

    asyncio.run(PipelineOrchestrator(db).run_event(event.id))
    assert matched == ["CVE-2022-0121"]
    assert acted == []


def test_matched_cve_runs_actions(monkeypatch):
    db = _session()
    source = _source(db)
    event = _event(db, source)
    acted = []

    async def fake_enrich(db, vuln, ai_fallback=True, source_fields=None):
        return vuln

    async def fake_match(db, vuln, ai_fallback=True):
        return [SimpleNamespace(id=1)]

    async def fake_act(db, vuln, audit=True, store=True):
        acted.append(vuln.cve_id)

    monkeypatch.setattr("app.pipeline.orchestrator.extract_from_event", _extract())
    monkeypatch.setattr("app.pipeline.orchestrator.enrich_cve", fake_enrich)
    monkeypatch.setattr("app.pipeline.orchestrator.match_assets", fake_match)
    monkeypatch.setattr("app.pipeline.orchestrator.take_action", fake_act)
    monkeypatch.setattr(
        "app.pipeline.orchestrator.get_settings",
        lambda: SimpleNamespace(ai_enabled=False, enrichment_enabled=True),
    )
    monkeypatch.setattr("app.pipeline.orchestrator.finalize_extract", AsyncMock())

    asyncio.run(PipelineOrchestrator(db).run_event(event.id))
    assert acted == ["CVE-2024-4844"]


def test_actions_queue_hides_unmatched():
    from app.api.pipeline import actions_queue
    from app.models.asset import Asset, AssetMatch
    from app.models.enums import PipelineStatus

    db = _session()
    unmatched = Vulnerability(
        cve_id="CVE-2022-0121",
        title="hoppscotch",
        status=PipelineStatus.MATCHED,
        pipeline_status="matching",
    )
    hit = Vulnerability(
        cve_id="CVE-2024-4844",
        title="epo",
        status=PipelineStatus.ACTIONED,
        pipeline_status="completed",
    )
    db.add_all([unmatched, hit])
    db.commit()
    db.refresh(hit)
    asset = Asset(name="ePO", vendor="Trellix", product="ePolicy Orchestrator")
    db.add(asset)
    db.commit()
    db.refresh(asset)
    db.add(AssetMatch(vulnerability_id=hit.id, asset_id=asset.id, method="local", confidence=1.0))
    db.commit()

    ids = [row["cve_id"] for row in actions_queue(db)["rows"]]
    assert "CVE-2024-4844" in ids
    assert "CVE-2022-0121" not in ids


def test_enqueue_from_worker_thread_reaches_asyncio_queue(monkeypatch):
    monkeypatch.setattr(InProcessQueue, "_rehydrate", lambda self, include_processing=True: None)

    async def idle(self):
        assert self._stopping is not None
        await self._stopping.wait()

    monkeypatch.setattr(InProcessQueue, "_worker", idle)

    async def main():
        q = InProcessQueue()
        await q.start()
        q.enqueue(11)
        q.enqueue(11)
        assert q._queue.qsize() == 1
        got = []

        def from_thread():
            q.enqueue(22)

        await asyncio.to_thread(from_thread)
        await asyncio.sleep(0)
        got.append(await q._queue.get())
        got.append(await q._queue.get())
        assert sorted(got) == [11, 22]
        await q.stop()

    asyncio.run(main())
