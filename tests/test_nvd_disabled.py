from app.config import Settings, get_settings


def test_nvd_is_off_unless_enabled(monkeypatch):
    monkeypatch.setenv("NVD_ENABLED", "false")
    get_settings.cache_clear()
    off = Settings()
    assert off.nvd_enabled is False
    assert off.nvd_configured is False

    monkeypatch.setenv("NVD_ENABLED", "true")
    on = Settings()
    assert on.nvd_enabled is True
    assert on.nvd_configured is True
    get_settings.cache_clear()


def test_epss_is_off_unless_enabled(monkeypatch):
    monkeypatch.setenv("ENRICHMENT_ENABLED", "true")
    monkeypatch.setenv("EPSS_ENABLED", "false")
    get_settings.cache_clear()
    off = Settings()
    assert off.epss_enabled is False
    assert off.epss_configured is False

    monkeypatch.setenv("EPSS_ENABLED", "true")
    on = Settings()
    assert on.epss_enabled is True
    assert on.epss_configured is True
    get_settings.cache_clear()


def test_enrichment_enabled_defaults_on():
    get_settings.cache_clear()
    assert Settings().enrichment_enabled is True

