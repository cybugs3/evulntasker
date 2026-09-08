from app.services.intel_parse import parse_intel


def test_parse_labeled_text():
    text = """
    Advisory
    CVE-2021-41773
    Vendor: Apache
    Product: HTTP Server
    Version: 2.4.49
    """
    rows = parse_intel(text)
    assert len(rows) == 1
    rec = rows[0]
    assert rec.cve_id == "CVE-2021-41773"
    assert rec.vendor == "Apache"
    assert rec.product == "HTTP Server"
    assert rec.version == "2.4.49"


def test_parse_csv_columns():
    text = "cve_id,vendor,product,version\nCVE-2021-44228,Apache,Log4j,2.14.1\n"
    rows = parse_intel(text, filename="intel.csv")
    assert rows[0].cve_id == "CVE-2021-44228"
    assert rows[0].vendor == "Apache"
    assert rows[0].product == "Log4j"
    assert rows[0].version == "2.14.1"


def test_parse_json_records():
    text = '{"records":[{"cve_id":"CVE-2024-3094","vendor":"Tukaani","product":"xz","version":"5.6.0"}]}'
    rows = parse_intel(text, filename="intel.json")
    assert rows[0].cve_id == "CVE-2024-3094"
    assert rows[0].vendor == "Tukaani"
    assert rows[0].product == "xz"


def test_parse_cpe_and_two_cves():
    text = """
    CVE-2021-44228 cpe:2.3:a:apache:log4j:2.14.1
    CVE-2021-45046
    Vendor: Apache
    Product: Log4j
    """
    rows = {row.cve_id: row for row in parse_intel(text)}
    assert "CVE-2021-44228" in rows
    assert rows["CVE-2021-44228"].vendor.lower() == "apache"
    assert "log4j" in (rows["CVE-2021-44228"].product or "").lower()
    assert rows["CVE-2021-45046"].cve_id == "CVE-2021-45046"
