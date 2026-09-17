from fastapi.testclient import TestClient

from app.api.sources import _source_out
from app.config import get_settings
from app.main import app, openapi_kwargs
from app.models.source import InputSource
from app.utils.http_basic import authorized, is_open_path
from app.utils.outbound_url import OutboundUrlError, assert_http_url
from app.utils.rate_limit import allow, reset_limits
from app.utils.textclean import email_domain_allowed, parse_email_domains


def test_production_hides_openapi():
    assert openapi_kwargs("production") == {
        "docs_url": None,
        "redoc_url": None,
        "openapi_url": None,
    }
    assert openapi_kwargs("development")["docs_url"] == "/docs"


def test_outbound_url_allows_https():
    assert assert_http_url("https://nvd.nist.gov/feeds/json")


def test_outbound_url_blocks_file_and_metadata():
    for url in (
        "file:///etc/passwd",
        "http://169.254.169.254/latest/meta-data",
        "http://metadata.google.internal/",
        "gopher://127.0.0.1:70/",
    ):
        try:
            assert_http_url(url)
        except OutboundUrlError:
            continue
        raise AssertionError(url)


def test_rate_limit_blocks_after_window_fills():
    reset_limits()
    path = "/api/settings/wipe-cve-data"
    for _ in range(3):
        assert allow(path, "1.2.3.4", now=1000.0) is True
    assert allow(path, "1.2.3.4", now=1001.0) is False
    assert allow(path, "9.9.9.9", now=1001.0) is True
    reset_limits()


def test_healthz_is_open_for_basic_auth():
    assert is_open_path("/healthz") is True
    assert is_open_path("/api/webhooks/abc") is True
    assert is_open_path("/") is False
    assert authorized("Basic bGFiOnNlY3JldA==", "lab", "secret") is True
    assert authorized("Basic bGFiOndyb25n", "lab", "secret") is False


def test_email_domain_allow_list():
    domains = parse_email_domains("corp.local, gmail.com")
    assert email_domain_allowed("alice@corp.local", domains) is True
    assert email_domain_allowed("bob@gmail.com", domains) is True
    assert email_domain_allowed("eve@evil.example", domains) is False
    assert email_domain_allowed("alice@corp.local", []) is True


def test_source_out_redacts_secrets():
    source = InputSource(
        name="smb-lab",
        source_type="smb",
        description="",
        config={"password": "super-secret", "username": "ad", "server": "fs.lab"},
        webhook_token="webhook-secret-token",
    )
    source.id = 9
    out = _source_out(source)
    assert "password" not in out.config
    assert out.config.get("username") == "ad"
    assert out.webhook_token is None
    assert out.webhook_token_set is True
    assert _source_out(source, reveal_webhook=True).webhook_token == "webhook-secret-token"


def test_basic_auth_env_blocks_ui(monkeypatch):
    monkeypatch.setenv("EVULNTASKER_BASIC_AUTH_USER", "lab")
    monkeypatch.setenv("EVULNTASKER_BASIC_AUTH_PASSWORD", "secret")
    get_settings.cache_clear()
    try:
        with TestClient(app) as client:
            assert client.get("/healthz").status_code == 200
            assert client.get("/").status_code == 401
            assert client.get("/", auth=("lab", "secret")).status_code == 200
    finally:
        monkeypatch.delenv("EVULNTASKER_BASIC_AUTH_USER", raising=False)
        monkeypatch.delenv("EVULNTASKER_BASIC_AUTH_PASSWORD", raising=False)
        get_settings.cache_clear()
