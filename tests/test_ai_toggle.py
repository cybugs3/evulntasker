import asyncio
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.settings.integrations import AiIn
from app.config import get_settings
from app.db.session import Base
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.pipeline.orchestrator import PipelineOrchestrator
from app.pipeline.step4_match import match_assets


def _session():
    import app.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def test_ai_configured_requires_key(monkeypatch):
    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("AI_API_KEY", "")
    get_settings.cache_clear()
    assert get_settings().ai_configured is False
    get_settings.cache_clear()


def test_ai_settings_payload_can_disable():
    body = AiIn(enabled=False, provider="gemini")
    assert body.enabled is False


def test_orchestrator_ai_follows_global_switch(monkeypatch):
    monkeypatch.setenv("AI_ENABLED", "false")
    get_settings.cache_clear()
    orch = PipelineOrchestrator(None)
    assert orch._ai_enabled(None) is False
    assert orch._ai_enabled(SimpleNamespace(ai_fallback_enabled=True)) is False
    get_settings.cache_clear()


def test_orchestrator_ai_respects_source_flag_when_globally_on(monkeypatch):
    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("AI_API_KEY", "test-key")
    get_settings.cache_clear()
    orch = PipelineOrchestrator(None)
    assert orch._ai_enabled(None) is True
    assert orch._ai_enabled(SimpleNamespace(ai_fallback_enabled=False)) is False
    get_settings.cache_clear()


def test_orchestrator_ai_stays_off_without_api_key(monkeypatch):
    monkeypatch.setenv("AI_ENABLED", "true")
    monkeypatch.setenv("AI_API_KEY", "")
    get_settings.cache_clear()
    orch = PipelineOrchestrator(None)
    assert orch._ai_enabled(None) is False
    assert orch._ai_enabled(SimpleNamespace(ai_fallback_enabled=True)) is False
    get_settings.cache_clear()


def test_save_ai_enable_without_key_writes_disabled(monkeypatch):
    captured = {}

    def fake_save(updates):
        captured.update(updates)

    monkeypatch.setattr("app.api.settings.integrations.save_env", fake_save)
    monkeypatch.setattr(
        "app.api.settings.integrations.get_app_settings",
        lambda: SimpleNamespace(ai_api_key=""),
    )
    from app.api.settings.integrations import save_ai

    result = save_ai(AiIn(enabled=True, provider="gemini"))
    assert result["ok"] is True
    assert result["enabled"] is False
    assert result["needs_key"] is True
    assert captured["AI_ENABLED"] == "false"
    assert "AI_API_KEY" not in captured


def test_save_ai_enable_with_new_key(monkeypatch):
    captured = {}

    def fake_save(updates):
        captured.update(updates)

    monkeypatch.setattr("app.api.settings.integrations.save_env", fake_save)
    monkeypatch.setattr(
        "app.api.settings.integrations.get_app_settings",
        lambda: SimpleNamespace(ai_api_key=""),
    )
    from app.api.settings.integrations import save_ai

    result = save_ai(AiIn(enabled=True, provider="gemini", api_key="secret"))
    assert result["enabled"] is True
    assert result["needs_key"] is False
    assert captured["AI_ENABLED"] == "true"
    assert captured["AI_API_KEY"] == "secret"


def test_match_skips_ai_when_globally_disabled(monkeypatch):
    monkeypatch.setenv("AI_ENABLED", "false")
    get_settings.cache_clear()
    called = []

    class Fake:
        available = False

        async def infer_ownership(self, *args, **kwargs):
            called.append(1)
            return {"owner_email": "ai@example.com"}

    monkeypatch.setattr("app.pipeline.step4_match.AICopilot", Fake)
    db = _session()
    db.add(
        Asset(
            name="host-1",
            vendor="Acme",
            product="Widget",
            active=True,
            source="local",
        )
    )
    vuln = Vulnerability(cve_id="CVE-2024-3094", vendor="Other", product="Thing")
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    matches = asyncio.run(match_assets(db, vuln, ai_fallback=True))
    assert matches == []
    assert called == []
    assert vuln.ai_matching_used is False
    get_settings.cache_clear()
