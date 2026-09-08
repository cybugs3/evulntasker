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
        assert ">Main<" in html or "Main</span>" in html
        assert "Input Sources" in html
        assert "Ingested today" in html
        assert "Hunts / detections" in html


def test_status_page_has_repository_queue():
    with TestClient(app) as client:
        html = client.get("/status").text
        assert "Vulnerability repository" in html
        assert "Integration status" in html


def test_inventory_page_is_manual_catalog():
    with TestClient(app) as client:
        html = client.get("/inventory").text
        assert "Internal systems" in html
        assert "Add system" in html
        assert "Import CSV" in html
        assert "Load sample catalog" not in html
        assert "Scheduled refresh" not in html


def test_incoming_cves_page():
    with TestClient(app) as client:
        html = client.get("/cves").text
        assert "Incoming CVEs" in html
        assert "Product type" in html
        assert "Severity" in html
        assert 'data-slot="alias"' not in html
        assert 'data-slot="cve-link"' in html
        data = client.get("/api/cves")
        assert data.status_code == 200
        body = data.json()
        assert "rows" in body


def test_settings_feeds_are_atom():
    with TestClient(app) as client:
        html = client.get("/settings").text
        assert "ATOM feeds" in html
        assert "Add ATOM feed" in html
        assert "Restore default ATOM" in html
        assert "Add SMB location" in html
        assert "tracking is by CVE number" not in html
        assert "existing IDs are updated" in html
        assert "Fetch interval" in html
        assert "Add intel source" in html
        assert "Restore NVD" in html
        assert "NVD 2.0" in html
        assert "FIRST EPSS" in html
        assert "Enable lookup" in html
        assert "Source name" in html
        assert "data-tab=\"enrichment\"" in html
        assert "Skip NVD, EPSS, and AI" in html
        assert "data-tab=\"intel\"" in html
        assert "When enrichment is on, Python (NVD + EPSS) runs first" in html
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
        assert ">System<" in html or "data-tab=\"system\"" in html
        assert "Reset system" in html
        assert "This will delete all table data" in html
        assert "Are you sure you want to continue?" in html
        assert "Wipe collected CVE data" not in html


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
        assert "CVEs received per source" in html
        assert "Selected source details" not in html


def test_enrichment_links_to_nvd_and_ai_settings():
    with TestClient(app) as client:
        html = client.get("/enrichment").text
        assert "/settings#enrichment" in html
        assert "/settings#intel" in html
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
