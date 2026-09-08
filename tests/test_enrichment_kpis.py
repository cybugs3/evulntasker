from types import SimpleNamespace

from app.api.pipeline import _has_intel


def test_has_intel_requires_nvd_or_epss_data():
    empty = SimpleNamespace(cvss_score=None, epss_score=None, enrichment={})
    assert _has_intel(empty) is False
    assert _has_intel(SimpleNamespace(cvss_score=9.8, epss_score=None, enrichment={})) is True
    assert _has_intel(SimpleNamespace(cvss_score=None, epss_score=0.12, enrichment={})) is True
    assert _has_intel(SimpleNamespace(cvss_score=None, epss_score=None, enrichment={"nvd": {"id": "x"}})) is True
