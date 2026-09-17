from app.utils.identity import clean_identity, derive_identity, ensure_identity, identity_for


def test_clean_identity_drops_placeholders():
    assert clean_identity("n/a") == ""
    assert clean_identity("N/A") == ""
    assert clean_identity("unknown") == ""
    assert clean_identity("-") == ""
    assert clean_identity("opswat") == "opswat"
    assert clean_identity("metadefender_core") == "metadefender core"


def test_derive_identity_from_opswat_advisory():
    title = (
        "Opswat Metadefender Core before 5.2.1 does not properly defend against "
        "potential HTML injection and XSS attacks."
    )
    vendor, product = derive_identity(title)
    assert vendor.lower() == "opswat"
    assert "metadefender" in product.lower()
    assert "core" in product.lower()


def test_identity_for_uses_title_when_nvd_says_na():
    vuln = type(
        "V",
        (),
        {
            "vendor": "n/a",
            "product": "n/a",
            "title": "Opswat Metadefender Core before 5.2.1 does not properly defend.",
            "description": "",
        },
    )()
    vendor, product = identity_for(vuln)
    assert vendor.lower() == "opswat"
    assert "metadefender" in product.lower()


def test_ensure_identity_clears_placeholders_and_fills():
    vuln = type(
        "V",
        (),
        {
            "vendor": "n/a",
            "product": "n/a",
            "affected_versions": "n/a",
            "title": "Opswat Metadefender Core before 5.2.1 does not properly defend.",
            "description": "",
        },
    )()
    assert ensure_identity(vuln) is True
    assert vuln.vendor.lower() == "opswat"
    assert "metadefender" in vuln.product.lower()
    assert vuln.affected_versions == ""
