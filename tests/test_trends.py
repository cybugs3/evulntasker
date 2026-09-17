from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.dashboard import build_trend_series, ingest_match_trends
from app.db.session import Base
from app.models.asset import Asset, AssetMatch
from app.models.enums import PipelineStatus
from app.models.vulnerability import Vulnerability
from app.services.workflow import build_workflow_snapshot


def test_trend_series_uses_workflow_flags_not_subtraction():
    now = datetime(2026, 9, 10, 16, 0, tzinfo=timezone.utc)
    rows = [
        {"created_at": now - timedelta(days=2), "matched": True, "unmatched": False, "waiting": False},
        {"created_at": now - timedelta(days=2, hours=3), "matched": False, "unmatched": True, "waiting": False},
        {"created_at": now - timedelta(days=1), "matched": False, "unmatched": False, "waiting": True},
    ]
    data = build_trend_series(rows, range_key="7d", now=now)
    assert data["granularity"] == "day"
    days = {row["t"][:10]: row for row in data["buckets"]}
    assert days["2026-09-08"]["ingested"] == 2
    assert days["2026-09-08"]["matched"] == 1
    assert days["2026-09-08"]["unmatched"] == 1
    assert days["2026-09-09"]["ingested"] == 1
    assert days["2026-09-09"]["waiting"] == 1
    assert data["totals"]["ingested"] == 3
    assert data["totals"]["matched"] == 1
    assert data["totals"]["unmatched"] == 1
    assert data["totals"]["waiting"] == 1
    assert data["totals"]["match_rate"] == 50


def test_trend_series_unknown_range_uses_seven_days():
    now = datetime(2026, 9, 10, tzinfo=timezone.utc)
    data = build_trend_series([], range_key="nope", now=now)
    assert data["range"] == "7d"
    assert data["buckets"]
    assert data["totals"]["ingested"] == 0
    assert data["totals"]["unmatched"] == 0


def test_trends_endpoint_follows_live_workflow():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, expire_on_commit=False)()
    ingested = Vulnerability(cve_id="CVE-2026-1111", title="new", pipeline_status="ingested")
    unmatched = Vulnerability(
        cve_id="CVE-2026-2222",
        title="miss",
        status=PipelineStatus.MATCHED,
        pipeline_status="matching",
        cvss_score=7.5,
        vendor="Other",
        product="Thing",
    )
    hit = Vulnerability(
        cve_id="CVE-2026-3333",
        title="hit",
        status=PipelineStatus.ACTIONED,
        pipeline_status="completed",
        cvss_score=8.0,
        vendor="Trellix",
        product="ePolicy Orchestrator",
    )
    db.add_all([ingested, unmatched, hit])
    now = datetime.now(timezone.utc)
    ingested.created_at = now
    unmatched.created_at = now
    hit.created_at = now
    db.commit()
    db.refresh(hit)
    asset = Asset(name="ePO", vendor="Trellix", product="ePolicy Orchestrator")
    db.add(asset)
    db.commit()
    db.refresh(asset)
    db.add(AssetMatch(vulnerability_id=hit.id, asset_id=asset.id, method="local", confidence=1.0))
    db.commit()

    payload = ingest_match_trends(db, range="7d")
    workflow = build_workflow_snapshot(db)
    assert payload["totals"]["ingested"] == 3
    assert payload["totals"]["matched"] == 1
    assert payload["totals"]["unmatched"] == workflow["summary"]["unmatched"] == 1
    assert payload["totals"]["match_rate"] == 50
