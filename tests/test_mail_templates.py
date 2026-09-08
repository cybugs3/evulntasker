from app.services.mail_templates import (
    flatten_ai_json,
    load_templates,
    message_context,
    render_hunt,
    render_owner,
    render_template,
    save_templates,
)


def test_render_template_uses_json_keys():
    text = render_template(
        "CVE {{cve_id}} hits {{vendor}} / {{product}} ({{product_type}}) {{versions}}\n{{summary}}",
        {
            "cve_id": "CVE-2024-1",
            "vendor": "Red Hat",
            "product": "kernel",
            "product_type": "os",
            "versions": "el9",
            "summary": "Local privilege escalation.",
        },
    )
    assert "CVE-2024-1" in text
    assert "Red Hat / kernel (os) el9" in text
    assert "Local privilege escalation." in text


def test_unknown_token_becomes_empty():
    assert render_template("start {{missing}} end", {}) == "start  end"


def test_flatten_ai_json_aliases_summary_and_versions():
    out = flatten_ai_json(
        {
            "vendor": "Apache",
            "summary": "Clear text",
            "versions": "2.4.x",
            "cwe_ids": ["CWE-79", "CWE-80"],
        }
    )
    assert out["description"] == "Clear text"
    assert out["affected_versions"] == "2.4.x"
    assert out["cwe_ids"] == "CWE-79, CWE-80"


def test_extra_ai_keys_are_available_in_template():
    ctx = flatten_ai_json({"vendor": "Linux", "exploit_complexity": "low"})
    assert render_template("complexity={{exploit_complexity}}", ctx) == "complexity=low"


def test_message_context_prefers_vuln_description_and_ai_json():
    class V:
        cve_id = "CVE-1"
        vendor = "Linux"
        product = "Kernel"
        product_type = "os"
        affected_versions = "5.14"
        description = "Owner-facing summary"
        attack_vector = "LOCAL"
        cwe_ids = ["CWE-416"]
        severity = "HIGH"
        priority = "P2"
        cvss_score = 7.8
        epss_score = 0.2
        enrichment = {"ai": {"vendor": "linux", "summary": "AI summary", "foo": "bar"}}

    ctx = message_context(V(), {"email": "alice@corp.local", "asset_name": "rhel-01"})
    assert ctx["cve_id"] == "CVE-1"
    assert ctx["foo"] == "bar"
    assert ctx["description"] == "Owner-facing summary"
    assert ctx["email"] == "alice@corp.local"
    assert ctx["asset_name"] == "rhel-01"


def test_save_and_load_templates(tmp_path, monkeypatch):
    path = tmp_path / "mail_templates.json"
    monkeypatch.setattr("app.services.mail_templates.template_path", lambda: path)
    save_templates(
        {
            "owner_subject": "FIX {{cve_id}}",
            "owner_body": "Vendor {{vendor}}",
            "hunt_subject": "HUNT {{cve_id}}",
            "hunt_body": "{{summary}}",
        }
    )
    loaded = load_templates()
    assert loaded["owner_subject"] == "FIX {{cve_id}}"
    assert "Vendor {{vendor}}" in loaded["owner_body"]
    assert path.is_file()


def test_render_owner_and_hunt_from_saved_template(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.mail_templates.template_path", lambda: tmp_path / "mail_templates.json")
    save_templates(
        {
            "owner_subject": "P {{cve_id}} {{product}}",
            "owner_body": "Hello {{asset_owner}}\n{{summary}}",
            "hunt_subject": "Hunt {{cve_id}}",
            "hunt_body": "{{sigma_rule}}",
        }
    )

    class V:
        cve_id = "CVE-9"
        vendor = "Apache"
        product = "httpd"
        product_type = "application"
        affected_versions = "2.4"
        description = "Readable summary"
        attack_vector = "NETWORK"
        cwe_ids = []
        severity = "HIGH"
        priority = "P1"
        cvss_score = 9.1
        epss_score = 0.4
        enrichment = {"ai": {"summary": "Readable summary"}}

    subject, body = render_owner(V(), {"asset_owner": "Alice", "product": "httpd"})
    assert subject == "P CVE-9 httpd"
    assert "Hello Alice" in body
    assert "Readable summary" in body
    hunt_subject, hunt_body = render_hunt(V(), {"sigma_rule": "title: hunt"})
    assert hunt_subject == "Hunt CVE-9"
    assert "title: hunt" in hunt_body
