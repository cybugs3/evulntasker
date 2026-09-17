import app.models  # noqa: F401
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.asset import Asset, AssetMatch
from app.models.enums import PipelineStatus
from app.models.source import InputSource
from app.models.vulnerability import Vulnerability
from app.services.wipe import delete_incoming_cves, wipe_collected_cve_data, wipe_internal_systems


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _seed(db):
    source = InputSource(
        name="local",
        source_type="scheduled",
        event_count=4,
        config={"seen": ["a"], "last_poll_at": "2026-09-17T07:00:00+00:00"},
    )
    asset = Asset(name="ePO", vendor="Trellix", product="ePolicy Orchestrator")
    vuln = Vulnerability(cve_id="CVE-2026-11111", title="test", status=PipelineStatus.MATCHED)
    db.add_all([source, asset, vuln])
    db.flush()
    db.add(AssetMatch(vulnerability_id=vuln.id, asset_id=asset.id, method="local"))
    db.commit()
    return source, asset, vuln


def test_wipe_internal_systems_keeps_cves_and_sources():
    db = _session()
    source, asset, vuln = _seed(db)

    result = wipe_internal_systems(db)

    assert result["ok"] is True
    assert result["deleted"]["assets"] == 1
    assert db.get(Asset, asset.id) is None
    assert db.scalar(select(AssetMatch).limit(1)) is None
    assert db.get(Vulnerability, vuln.id) is not None
    kept = db.get(InputSource, source.id)
    assert kept is not None
    assert kept.event_count == 4
    assert (kept.config or {}).get("seen") == ["a"]


def test_wipe_cve_data_keeps_internal_systems():
    db = _session()
    source, asset, vuln = _seed(db)

    result = wipe_collected_cve_data(db)

    assert result["ok"] is True
    assert db.get(Vulnerability, vuln.id) is None
    assert db.scalar(select(AssetMatch).limit(1)) is None
    assert db.get(Asset, asset.id) is not None
    kept = db.get(InputSource, source.id)
    assert kept is not None
    assert kept.event_count == 0
    assert "seen" not in (kept.config or {})
    assert "last_poll_at" not in (kept.config or {})


def test_delete_incoming_cves_removes_only_selected():
    db = _session()
    source, asset, vuln = _seed(db)
    other = Vulnerability(cve_id="CVE-2026-22222", title="keep", status=PipelineStatus.INGESTED)
    db.add(other)
    db.commit()

    result = delete_incoming_cves(db, ["cve-2026-11111", "CVE-2026-11111"])

    assert result["ok"] is True
    assert result["deleted"] == 1
    assert db.get(Vulnerability, vuln.id) is None
    assert db.get(Vulnerability, other.id) is not None
    assert db.get(Asset, asset.id) is not None
    assert db.scalar(select(AssetMatch).limit(1)) is None
    assert db.get(InputSource, source.id) is not None


def test_delete_incoming_cves_rejects_empty():
    db = _session()
    try:
        delete_incoming_cves(db, ["  ", ""])
    except ValueError as exc:
        assert "No CVEs selected" in str(exc)
    else:
        raise AssertionError("expected ValueError")
