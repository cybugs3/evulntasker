import asyncio
from types import SimpleNamespace

from app.pipeline.step2_extract import extract_from_event


def test_regex_cve_does_not_call_or_count_ai(monkeypatch):
    called = []

    class Fake:
        available = True

        async def extract(self, text):
            called.append(text)
            return {"cve_ids": ["CVE-2024-9999"]}

    monkeypatch.setattr("app.pipeline.step2_extract.AICopilot", Fake)
    event = SimpleNamespace(id=1, payload={"cve_id": "CVE-2024-3094"}, raw_text="Advisory CVE-2024-3094")
    result = asyncio.run(extract_from_event(event, ai_fallback=True))
    assert result.cve_ids == ["CVE-2024-3094"]
    assert result.ai_used is False
    assert called == []


def test_ai_counts_only_when_it_finds_a_cve(monkeypatch):
    class Fake:
        available = True

        async def extract(self, text):
            return {"cve_ids": ["CVE-2024-3094"], "vendor": "xz"}

    monkeypatch.setattr("app.pipeline.step2_extract.AICopilot", Fake)
    event = SimpleNamespace(id=1, payload={}, raw_text="an advisory with no identifier")
    result = asyncio.run(extract_from_event(event, ai_fallback=True))
    assert result.cve_ids == ["CVE-2024-3094"]
    assert result.ai_used is True


def test_unconfigured_ai_is_not_counted(monkeypatch):
    class Fake:
        available = False

        async def extract(self, text):
            raise AssertionError("AI must not run when unconfigured")

    monkeypatch.setattr("app.pipeline.step2_extract.AICopilot", Fake)
    event = SimpleNamespace(id=1, payload={}, raw_text="an advisory with no identifier")
    result = asyncio.run(extract_from_event(event, ai_fallback=True))
    assert result.cve_ids == []
    assert result.ai_used is False
