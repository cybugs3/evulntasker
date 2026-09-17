from fastapi.testclient import TestClient

from app.main import app


def test_healthz():
    with TestClient(app) as client:
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


def test_dashboard_is_english():
    with TestClient(app) as client:
        html = client.get("/").text
        assert "Overview Dashboards" in html
        assert "Databases" in html
        assert "Internal systems" in html
        assert "Incoming CVEs" in html
        assert "CVE Tracker" not in html
        assert ">Main<" in html or "Main</span>" in html
        assert "Input Sources" in html
        assert "Catalog" not in html
        assert 'href="/repositories"' not in html
        assert "Ingested today" in html
        assert "Hunts / detections" in html
        assert 'id="page-updated"' in html
        assert 'id="refresh-btn"' not in html
        assert "AI fallback" not in html


def test_status_page_has_repository_queue():
    with TestClient(app) as client:
        html = client.get("/status").text
        assert "Vulnerability repository" in html
        assert "Integration status" in html
        assert 'id="page-updated"' in html
        assert 'id="refresh-btn"' not in html


def test_inventory_page_is_manual_catalog():
    with TestClient(app) as client:
        html = client.get("/inventory").text
        assert "Internal systems" in html
        assert "Add system" in html
        assert "Import CSV" in html
        assert "Export CSV" in html
        assert "Select to delete" in html
        assert 'id="inv-select-ok"' in html
        assert 'id="inv-select-modal"' in html
        assert "Load sample catalog" not in html
        assert "Scheduled refresh" not in html


def test_incoming_cves_page():
    with TestClient(app) as client:
        html = client.get("/cves").text
        assert "Incoming CVEs" in html
        assert "Product type" in html
        assert "Severity" in html
        assert ">Match<" in html or "Match</th>" in html
        assert 'data-slot="alias"' not in html
        assert 'data-slot="cve-link"' in html
        assert "Click a row for Live Workflow stations" in html
        assert "Select to delete" in html
        assert 'id="cve-select-ok"' in html
        assert 'id="cve-select-modal"' in html
        data = client.get("/api/cves")
        assert data.status_code == 200
        body = data.json()
        assert "rows" in body


def test_old_tracker_url_redirects_to_incoming_cves():
    with TestClient(app) as client:
        response = client.get("/tracker", follow_redirects=False)
        assert response.status_code in {301, 302, 307, 308}
        assert "/cves" in (response.headers.get("location") or "")


def test_settings_feeds_are_atom():
    with TestClient(app) as client:
        html = client.get("/settings").text
        assert "ATOM feeds" in html
        assert "Add ATOM feed" in html
        assert "Restore default ATOM" in html
        assert "Add SMB location" in html
        assert "tracking is by CVE number" not in html
        assert "Enable or pause each ATOM feed" in html
        assert "Enable polling only fetches ATOM/RSS" not in html
        assert "Fetch interval" in html
        assert "Ignore CVEs published before" in html
        assert "Applies to every incoming path" in html
        assert "Source name" in html
        assert "data-tab=\"enrichment\"" in html
        assert "Skip NVD and EPSS" in html
        assert "data-tab=\"intel\"" not in html
        assert "href=\"#feeds/web\"" in html
        assert "NVD and EPSS endpoints stay in ATOM feeds" in html
        assert "Enable Google Gemini" in html
        assert "Enable Azure OpenAI" in html
        assert "Enable GitHub Copilot" in html
        assert "Email (mail relay)" in html
        assert "owner_email" in html
        assert "not one shared mailbox" in html
        assert 'data-tab="message"' in html
        assert "{{name}}" in html or "{{cve_id}}" in html
        assert "SMTP host" in html
        assert "Enable AI module" not in html
        assert "Only one AI module can be enabled" in html
        assert "AI is optional" in html
        assert 'data-tab="reset"' in html
        assert ">Reset<" in html
        assert "Reset Internal systems" in html
        assert "Delete all CVEs" in html
        assert "This will delete Internal systems" in html
        assert "This will delete all CVE data" in html
        assert "Are you sure you want to continue?" in html
        assert "Wipe collected CVE data" not in html
        assert "Reset system" not in html
        assert "AI fallback" not in html
        assert "Requires an API key" in html


def test_repositories_url_redirects_to_input_sources():
    with TestClient(app) as client:
        response = client.get("/repositories", follow_redirects=False)
        assert response.status_code in {301, 302, 307, 308}
        assert "/sources" in (response.headers.get("location") or "")


def test_sources_page_lists_ingest_channels():
    with TestClient(app) as client:
        html = client.get("/sources").text
        assert "Input Sources" in html
        assert "Vulnerability Repositories" not in html
        assert "Enable/Pause controls automatic polling" in html
        assert "Settings → Feeds" in html
        assert "Sync now" in html
        assert 'id="page-updated"' in html
        assert "Unique CVE records stored" in html


def test_repository_cve_counts_are_not_seed_placeholders():
    with TestClient(app) as client:
        rows = client.get("/api/repositories").json()
        assert isinstance(rows, list)
        for row in rows:
            assert "cve_count" in row
            assert row["cve_count"] != 280000
            if row.get("feed_type") in {"nvd", "epss"}:
                assert row["cve_count"] >= 0


def test_atom_feed_save_stores_intel_start_date(monkeypatch):
    captured: dict[str, str] = {}
    monkeypatch.setattr(
        "app.api.settings.feeds.save_env",
        lambda updates: captured.update(updates),
    )
    with TestClient(app) as client:
        resp = client.put(
            "/api/settings/web-api",
            json={
                "enabled": False,
                "name": "ATOM feeds",
                "feeds": [],
                "intel_start_date": "2023-06-01",
            },
        )
    assert resp.status_code == 200
    assert captured.get("INTEL_START_DATE") == "2023-06-01"


def test_nvd_lookup_is_off_until_enabled():
    with TestClient(app) as client:
        items = client.get("/api/integrations").json()["integrations"]
        names = [item["name"] for item in items]
        assert "ATOM feeds" in names
        assert "NVD lookup" in names
        assert "NVD API" not in names
        assert "AI module" in names
        assert "AI Co-Pilot" not in names
        nvd = next(item for item in items if item["name"] == "NVD lookup")
        assert nvd["ok"] is False
        epss = next(item for item in items if item["name"] == "EPSS lookup")
        assert epss["ok"] is False


def test_sources_page_counts_cves():
    with TestClient(app) as client:
        html = client.get("/sources").text
        assert ">CVEs<" in html
        assert ">Events<" not in html
        assert "Configure sources" in html
        assert "Selected source details" not in html
        assert "Inline CVE" in html
        assert "Ingest CVE" in html
        assert "Save CVE, matches, and tickets" not in html


def test_workflow_page_has_inline_cve_bar():
    with TestClient(app) as client:
        html = client.get("/workflow").text
        assert "Inline CVE" in html
        assert "Ingest CVE" in html
        assert 'id="inline-cve-form"' in html
        assert 'id="wf-dossier"' in html


def test_cve_page_has_rerun_and_debug_buttons():
    with TestClient(app) as client:
        html = client.get("/vulnerabilities/CVE-2024-1234").text
        assert 'id="reprocess-btn"' in html
        assert "Re-run pipeline" in html
        assert 'id="debug-btn"' in html
        assert "Run debugger" in html


def test_debugger_does_not_offer_save():
    with TestClient(app) as client:
        html = client.get("/debug").text
        assert "Save CVE, matches, and tickets" not in html
        assert "debug-persist" not in html
        assert "never writes" in html
        assert "/sources" in html


def test_enrichment_links_to_nvd_and_ai_settings():
    with TestClient(app) as client:
        html = client.get("/enrichment").text
        assert "/settings#enrichment" in html
        assert "/settings#feeds/web" in html
        assert "/settings#ai" in html


def test_actions_page_shows_action_status():
    with TestClient(app) as client:
        html = client.get("/actions").text
        assert "Action status" in html
        assert 'id="ticketing-hint"' in html
        data = client.get("/api/pipeline/actions").json()
        assert "connected" in data["ticketing"]
        assert "provider_label" in data["ticketing"]
        for row in data.get("rows") or []:
            assert row["action_state"] in {"not_connected", "waiting", "created"}
            assert row["action_label"]
