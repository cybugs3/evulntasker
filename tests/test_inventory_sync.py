from types import SimpleNamespace

from app.pipeline.step4_match import version_overlap
from app.services.inventory_sync import is_placeholder_asset, parse_csv_text, sample_csv_text


def test_parse_csv_required_columns():
    rows = parse_csv_text(
        "vendor,product,product_type,version\n"
        "apache,http server,web-server,2.4.58\n"
    )
    assert len(rows) == 1
    assert rows[0]["vendor"] == "apache"
    assert rows[0]["product"] == "http server"
    assert rows[0]["product_type"] == "web-server"
    assert rows[0]["version"] == "2.4.58"


def test_parse_csv_header_aliases():
    rows = parse_csv_text(
        "Manufacturer,Software,Type,Version\n"
        "Cisco,IOS XE,network,17.9.4\n"
    )
    assert rows[0]["vendor"] == "Cisco"
    assert rows[0]["product"] == "IOS XE"
    assert rows[0]["product_type"] == "network"
    assert rows[0]["version"] == "17.9.4"


def test_parse_csv_skips_empty_rows():
    rows = parse_csv_text("vendor,product,product_type,version\n,,,\napache,httpd,web-server,2.4\n")
    assert len(rows) == 1
    assert rows[0]["product"] == "httpd"


def test_export_catalog_csv_includes_rows_and_round_trips():
    import app.models  # noqa: F401
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.session import Base
    from app.models.asset import Asset
    from app.services.inventory_sync import export_catalog_csv, parse_csv_text

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, expire_on_commit=False)()
    db.add(
        Asset(
            name="ePO",
            vendor="Trellix",
            product="ePolicy Orchestrator",
            system_type="endpoint",
            version="5.10.0",
            owner_name="Guy",
            owner_email="guy.zwerdling@gmail.com",
            team="Platform",
        )
    )
    db.commit()
    text = export_catalog_csv(db)
    assert text.splitlines()[0] == "vendor,product,product_type,version,owner_name,owner_email,team,last_update"
    rows = parse_csv_text(text)
    assert len(rows) == 1
    assert rows[0]["vendor"] == "Trellix"
    assert rows[0]["product"] == "ePolicy Orchestrator"
    assert rows[0]["version"] == "5.10.0"
    assert rows[0]["owner_email"] == "guy.zwerdling@gmail.com"


def test_csv_template_is_headers_only():
    text = sample_csv_text()
    rows = parse_csv_text(text)
    assert rows == []
    assert "vendor" in text
    assert "owner_email" in text
    assert "example.com" not in text


def test_parse_csv_strips_rtl_email_and_float_version():
    rows = parse_csv_text(
        "vendor,product,product_type,version,owner_email\n"
        "canonical,ubuntu,linux,24.039999999999999,guy@corp.local\u200f\n"
    )
    assert rows[0]["version"] == "24.04"
    assert rows[0]["owner_email"] == "guy@corp.local"


def test_scrub_catalog_fields_cleans_stored_rows():
    import app.models  # noqa: F401
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.session import Base
    from app.models.asset import Asset
    from app.services.inventory_sync import scrub_catalog_fields

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, expire_on_commit=False)()
    db.add(
        Asset(
            name="ubuntu",
            vendor="canonical",
            product="ubuntu",
            version="24.039999999999999",
            owner_email="guy@corp.local\u200f",
        )
    )
    db.commit()
    changed = scrub_catalog_fields(db)
    db.commit()
    row = db.query(Asset).one()
    assert changed == 1
    assert row.version == "24.04"
    assert row.owner_email == "guy@corp.local"


def test_placeholder_assets_are_demo_rows():
    assert is_placeholder_asset(SimpleNamespace(name="AI-mapped ftp", owner_email=""))
    assert is_placeholder_asset(SimpleNamespace(name="httpd", owner_email="maya.cohen@example.com"))
    assert not is_placeholder_asset(SimpleNamespace(name="httpd", owner_email="ops@corp.local"))


def test_version_overlap_exact():
    vuln = SimpleNamespace(affected_versions="2.4.0 - 2.4.58", version=None)
    keep, bump = version_overlap("2.4.58", vuln)
    assert keep is True
    assert bump > 0


def test_version_overlap_empty_does_not_block():
    vuln = SimpleNamespace(affected_versions=None, version=None)
    keep, bump = version_overlap("2.4.58", vuln)
    assert keep is True
    assert bump == 0.0


def test_version_mismatch_excluded():
    vuln = SimpleNamespace(affected_versions="1.0.0", version=None)
    keep, _bump = version_overlap("2.4.58", vuln)
    assert keep is False


def test_remote_inventory_inserts_new_equipment_only():
    import app.models  # noqa: F401
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.session import Base
    from app.models.asset import Asset
    from app.services.inventory_sync import upsert_rows

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, expire_on_commit=False)()
    first = upsert_rows(
        db,
        "cmdb",
        [{"vendor": "Trellix", "product": "ePO", "version": "5.10", "owner_email": "old@corp.local"}],
    )
    assert first["created"] == 1
    assert first["updated"] == 0
    second = upsert_rows(
        db,
        "cmdb",
        [
            {"vendor": "Trellix", "product": "ePO", "version": "5.10", "owner_email": "new@corp.local"},
            {"vendor": "Red Hat", "product": "RHEL", "version": "9", "owner_email": "linux@corp.local"},
        ],
    )
    assert second["created"] == 1
    assert second["updated"] == 0
    epo = db.query(Asset).filter_by(product="ePO").one()
    assert epo.owner_email == "old@corp.local"
    assert db.query(Asset).count() == 2


def test_delete_assets_removes_only_selected():
    import app.models  # noqa: F401
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.session import Base
    from app.models.asset import Asset, AssetMatch
    from app.models.enums import PipelineStatus
    from app.models.vulnerability import Vulnerability
    from app.services.inventory_sync import delete_assets

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, expire_on_commit=False)()
    keep = Asset(name="keep", vendor="Red Hat", product="RHEL")
    drop = Asset(name="drop", vendor="Trellix", product="ePO")
    vuln = Vulnerability(cve_id="CVE-2026-33333", title="test", status=PipelineStatus.MATCHED)
    db.add_all([keep, drop, vuln])
    db.flush()
    db.add(AssetMatch(vulnerability_id=vuln.id, asset_id=drop.id, method="local"))
    db.commit()

    deleted = delete_assets(db, [drop.id, drop.id])
    assert deleted == 1
    assert db.get(Asset, drop.id) is None
    assert db.get(Asset, keep.id) is not None
    assert db.get(Vulnerability, vuln.id) is not None
    assert db.query(AssetMatch).count() == 0


def test_version_overlap_nvd_prose_does_not_block():
    vuln = SimpleNamespace(
        affected_versions="All versions below ePO 5.10 Service Pack 1 Update 2",
        version=None,
    )
    keep, bump = version_overlap("5.10.0", vuln)
    assert keep is True
    assert bump > 0


def test_version_overlap_advisory_family_covers_vendor_build():
    vuln = SimpleNamespace(
        affected_versions="9.0",
        version=None,
        title="Ivanti Connect Secure 9.x, 22.x",
        description="ICS 9.x, 22.x are affected.",
    )
    keep, bump = version_overlap("22.7R2.4", vuln)
    assert keep is True
    assert bump > 0


def test_version_overlap_numeric_minor_does_not_cover_other_major():
    vuln = SimpleNamespace(affected_versions="9.0", version=None, title="", description="")
    keep, _bump = version_overlap("22.7R2.4", vuln)
    assert keep is False


def test_version_overlap_same_major_different_minor_without_family():
    vuln = SimpleNamespace(affected_versions="9.0", version=None, title="", description="")
    keep, _bump = version_overlap("9.1R18", vuln)
    assert keep is False
