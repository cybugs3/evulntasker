from datetime import datetime, timezone

from app.utils.cve import extract_cves, priority_from_scores, severity_from_cvss
from app.utils.jsonutil import jsonable


def test_extract_unique_cves():
    text = "Advisory for cve-2024-3094 and CVE-2024-3094 plus CVE-2021-44228."
    assert extract_cves(text) == ["CVE-2024-3094", "CVE-2021-44228"]


def test_severity_bands():
    assert severity_from_cvss(9.8) == "CRITICAL"
    assert severity_from_cvss(7.5) == "HIGH"
    assert severity_from_cvss(5.0) == "MEDIUM"
    assert severity_from_cvss(None) == "UNKNOWN"


def test_priority_combines_epss():
    assert priority_from_scores(8.1, 0.7) == "P1"
    assert priority_from_scores(4.3, 0.01) == "P3"


def test_jsonable_datetimes():
    from datetime import datetime, timezone

    from app.utils.jsonutil import jsonable

    payload = jsonable({"when": datetime(2024, 1, 2, tzinfo=timezone.utc)})
    assert payload["when"].startswith("2024-01-02")
