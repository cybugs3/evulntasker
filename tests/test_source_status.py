from types import SimpleNamespace

from app.api.settings.common import record_source_error


def test_disabled_source_does_not_keep_error():
    source = SimpleNamespace(enabled=False, last_error="Exchange server and username are required")
    record_source_error(source, "Exchange server and username are required")
    assert source.last_error is None


def test_enabled_source_keeps_error():
    source = SimpleNamespace(enabled=True, last_error=None)
    record_source_error(source, "connection refused")
    assert source.last_error == "connection refused"
