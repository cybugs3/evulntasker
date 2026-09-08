from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.pipeline.step4_match import is_linux_asset, is_linux_cve, match_local_assets


def _session():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _asset(**kwargs) -> Asset:
    defaults = dict(
        name="host-1",
        vendor="REDHAT",
        product="Enterprise Linux",
        system_type="linux",
        version="9.4",
        active=True,
        source="local",
    )
    defaults.update(kwargs)
    return Asset(**defaults)


def _vuln(**kwargs) -> Vulnerability:
    defaults = dict(
        cve_id="CVE-2026-52923",
        vendor="Linux",
        product="Linux Kernel",
        product_type="os",
        affected_versions="6.6",
    )
    defaults.update(kwargs)
    return Vulnerability(**defaults)


def test_linux_kernel_cve_matches_redhat_linux_type():
    db = _session()
    asset = _asset()
    vuln = _vuln()
    db.add_all([asset, vuln])
    db.commit()
    db.refresh(asset)
    db.refresh(vuln)

    assert is_linux_cve(vuln)
    assert is_linux_asset(asset)
    hits = match_local_assets(db, vuln)
    assert [row[0].id for row in hits] == [asset.id]


def test_linux_kernel_cve_does_not_match_apache():
    db = _session()
    asset = _asset(
        name="web-1",
        vendor="Apache",
        product="HTTP Server",
        system_type="web-server",
        version="2.4.58",
    )
    vuln = _vuln()
    db.add_all([asset, vuln])
    db.commit()
    db.refresh(vuln)

    hits = match_local_assets(db, vuln)
    assert hits == []


def test_apache_cve_still_matches_http_server():
    db = _session()
    asset = _asset(
        name="web-1",
        vendor="Apache",
        product="HTTP Server",
        system_type="web-server",
        version="2.4.58",
    )
    vuln = _vuln(
        cve_id="CVE-2024-38474",
        vendor="Apache",
        product="HTTP Server",
        product_type="application",
        affected_versions="2.4.58",
    )
    db.add_all([asset, vuln])
    db.commit()
    db.refresh(vuln)

    hits = match_local_assets(db, vuln)
    assert len(hits) == 1
    assert hits[0][0].product == "HTTP Server"


def test_rhel_version_does_not_block_kernel_cve():
    db = _session()
    asset = _asset(version="9.4")
    vuln = _vuln(affected_versions="6.6.2")
    db.add_all([asset, vuln])
    db.commit()
    db.refresh(vuln)

    hits = match_local_assets(db, vuln)
    assert len(hits) == 1


def test_oracle_database_is_not_treated_as_linux_os():
    asset = _asset(
        vendor="Oracle",
        product="Database",
        system_type="application",
        version="19c",
    )
    vuln = _vuln()
    assert is_linux_cve(vuln)
    assert not is_linux_asset(asset)


def test_is_linux_cve_from_nvd_style_names():
    vuln = SimpleNamespace(vendor="linux", product="linux kernel", product_type=None)
    assert is_linux_cve(vuln)
