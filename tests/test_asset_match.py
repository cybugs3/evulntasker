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


def test_linux_kernel_cve_does_not_match_windows_or_glibc():
    db = _session()
    linux = _asset()
    windows = _asset(
        name="windows_11",
        vendor="microsoft",
        product="windows_11",
        system_type="os",
        version="24H2",
    )
    glibc = _asset(
        name="glibc",
        vendor="gnu",
        product="glibc",
        system_type="code_library",
        version="2.39",
    )
    vuln = _vuln()
    db.add_all([linux, windows, glibc, vuln])
    db.commit()
    db.refresh(vuln)

    assert not is_linux_asset(windows)
    assert not is_linux_asset(glibc)
    hits = match_local_assets(db, vuln)
    assert [row[0].product for row in hits] == ["Enterprise Linux"]


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


def test_unenriched_cve_is_not_linux_family():
    vuln = SimpleNamespace(vendor="", product="", product_type="os")
    assert not is_linux_cve(vuln)


def test_unenriched_cve_matches_no_inventory_rows():
    db = _session()
    linux = _asset()
    apache = _asset(
        name="web-1",
        vendor="Apache",
        product="HTTP Server",
        system_type="web-server",
        version="2.4.58",
    )
    oracle = _asset(
        name="db-1",
        vendor="Oracle",
        product="Database",
        system_type="application",
        version="19c",
    )
    vuln = _vuln(vendor="", product="", product_type="", affected_versions="")
    db.add_all([linux, apache, oracle, vuln])
    db.commit()
    db.refresh(vuln)

    hits = match_local_assets(db, vuln)
    assert hits == []


def test_product_only_does_not_match_unrelated_assets():
    db = _session()
    linux = _asset()
    apache = _asset(
        name="web-1",
        vendor="Apache",
        product="HTTP Server",
        system_type="web-server",
        version="2.4.58",
    )
    vuln = _vuln(
        cve_id="CVE-2024-38474",
        vendor="",
        product="HTTP Server",
        product_type="application",
        affected_versions="2.4.58",
    )
    db.add_all([linux, apache, vuln])
    db.commit()
    db.refresh(vuln)

    hits = match_local_assets(db, vuln)
    assert [row[0].product for row in hits] == ["HTTP Server"]


def test_nvd_placeholder_identity_matches_opswat_from_title():
    db = _session()
    asset = _asset(
        name="metadefender_core",
        vendor="opswat",
        product="metadefender_core",
        system_type="file_security",
        version="",
    )
    apache = _asset(
        name="web-1",
        vendor="Apache",
        product="HTTP Server",
        system_type="web-server",
        version="2.4.58",
    )
    vuln = _vuln(
        cve_id="CVE-2023-25364",
        vendor="n/a",
        product="n/a",
        product_type="",
        affected_versions="n/a",
        title="Opswat Metadefender Core before 5.2.1 does not properly defend against potential HTML injection and XSS attacks.",
        description="Opswat Metadefender Core before 5.2.1 does not properly defend against potential HTML injection and XSS attacks.",
    )
    db.add_all([asset, apache, vuln])
    db.commit()
    db.refresh(vuln)

    hits = match_local_assets(db, vuln)
    assert [row[0].vendor for row in hits] == ["opswat"]
    assert hits[0][0].product == "metadefender_core"


_IVANTI_46805 = dict(
    cve_id="CVE-2023-46805",
    vendor="ivanti",
    product="connect secure",
    product_type="application",
    affected_versions="9.0",
    title="An authentication bypass in Ivanti Connect Secure and Ivanti Policy Secure (9.x, 22.x) allows an attacker to access restricted resources.",
    description="ICS 9.x, 22.x and Ivanti Policy Secure gateways are affected. Fixed in 22.7R2.4.",
)


def test_ivanti_connect_secure_22x_family_matches_catalog_build():
    db = _session()
    asset = _asset(
        name="ics-gw",
        vendor="ivanti",
        product="connect_secure",
        system_type="vpn",
        version="22.7R2.4",
    )
    vuln = _vuln(**_IVANTI_46805)
    db.add_all([asset, vuln])
    db.commit()
    db.refresh(vuln)

    hits = match_local_assets(db, vuln)
    assert [row[0].product for row in hits] == ["connect_secure"]


def test_ivanti_policy_secure_does_not_match_on_secure_token():
    db = _session()
    asset = _asset(
        name="ips-gw",
        vendor="ivanti",
        product="Policy Secure",
        system_type="vpn",
        version="9.1R18",
    )
    vuln = _vuln(**_IVANTI_46805)
    db.add_all([asset, vuln])
    db.commit()
    db.refresh(vuln)

    hits = match_local_assets(db, vuln)
    assert hits == []


def test_ivanti_connect_secure_does_not_match_unrelated_major():
    db = _session()
    asset = _asset(
        name="ics-gw",
        vendor="ivanti",
        product="connect_secure",
        system_type="vpn",
        version="22.7R2.4",
    )
    vuln = _vuln(
        cve_id="CVE-2023-46805",
        vendor="ivanti",
        product="connect secure",
        product_type="application",
        affected_versions="9.0",
        title="An authentication bypass in Ivanti Connect Secure 9.0",
        description="Only the 9.0 branch is listed as affected.",
    )
    db.add_all([asset, vuln])
    db.commit()
    db.refresh(vuln)

    hits = match_local_assets(db, vuln)
    assert hits == []
