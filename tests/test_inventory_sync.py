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


def test_csv_template_is_headers_only():
    text = sample_csv_text()
    rows = parse_csv_text(text)
    assert rows == []
    assert "vendor" in text
    assert "owner_email" in text
    assert "example.com" not in text


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
