from app.config import get_settings
from app.services import database_settings as dbs


def _reload(monkeypatch, **env):
    monkeypatch.delenv("EVULNTASKER_DATABASE_URL", raising=False)
    monkeypatch.delenv("VULNINTEL_DATABASE_URL", raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    return get_settings()


def test_reads_evulntasker_database_url(monkeypatch):
    settings = _reload(monkeypatch, EVULNTASKER_DATABASE_URL="sqlite:///./data/new.db")
    assert settings.database_url == "sqlite:///./data/new.db"


def test_reads_legacy_vulnintel_database_url(monkeypatch):
    settings = _reload(monkeypatch, VULNINTEL_DATABASE_URL="sqlite:///./data/legacy.db")
    assert settings.database_url == "sqlite:///./data/legacy.db"


def test_evulntasker_prefix_wins_over_legacy(monkeypatch):
    settings = _reload(
        monkeypatch,
        EVULNTASKER_DATABASE_URL="sqlite:///./data/new.db",
        VULNINTEL_DATABASE_URL="sqlite:///./data/legacy.db",
    )
    assert settings.database_url == "sqlite:///./data/new.db"


def test_write_database_url_uses_new_key_and_keeps_legacy_in_sync(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("VULNINTEL_DATABASE_URL=sqlite:///./data/old.db\n", encoding="utf-8")
    monkeypatch.setattr(dbs, "env_path", lambda: env_file)
    get_settings.cache_clear()

    dbs.write_database_url("sqlite:///./data/evulntasker.db")
    text = env_file.read_text(encoding="utf-8")
    assert "EVULNTASKER_DATABASE_URL=sqlite:///./data/evulntasker.db" in text
    assert "VULNINTEL_DATABASE_URL=sqlite:///./data/evulntasker.db" in text
