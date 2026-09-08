"""Owner / hunt email templates filled from AI JSON field names."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

TOKEN_RE = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")

TEMPLATE_KEYS = (
    "owner_subject",
    "owner_body",
    "hunt_subject",
    "hunt_body",
)

# Canonical AI enrichment JSON keys. Extra keys the model returns also work as {{name}}.
AI_JSON_FIELDS = (
    "cve_id",
    "vendor",
    "product",
    "product_type",
    "versions",
    "summary",
    "description",
    "attack_vector",
    "cwe_ids",
)

CONTEXT_FIELDS = AI_JSON_FIELDS + (
    "severity",
    "priority",
    "cvss_score",
    "epss_score",
    "asset_name",
    "asset_owner",
    "email",
    "username",
    "team",
    "system_type",
    "version",
    "sigma_rule",
    "kql",
    "xql",
    "aqk",
    "ekql",
)

DEFAULTS = {
    "owner_subject": "[{{priority}}] {{cve_id}} — {{product}}",
    "owner_body": (
        "Vulnerability {{cve_id}} requires owner action.\n"
        "\n"
        "What this vulnerability does\n"
        "{{description}}\n"
        "\n"
        "Details\n"
        "Severity: {{severity}} ({{priority}})\n"
        "CVSS: {{cvss_score}}  EPSS: {{epss_score}}\n"
        "Attack vector: {{attack_vector}}\n"
        "Vendor / product: {{vendor}} / {{product}}\n"
        "Product type: {{product_type}}  Affected versions: {{versions}}\n"
        "System type: {{system_type}}  Version: {{version}}\n"
        "Asset: {{asset_name}}\n"
        "Owner: {{asset_owner}} ({{username}}) <{{email}}>\n"
        "Team: {{team}}\n"
    ),
    "hunt_subject": "[HUNT] {{cve_id}} — Sigma/SIEM detections",
    "hunt_body": (
        "Threat hunting task for {{cve_id}} ({{severity}}).\n"
        "\n"
        "What this vulnerability does\n"
        "{{description}}\n"
        "\n"
        "Vendor/product: {{vendor}} / {{product}}\n"
        "Product type: {{product_type}}  Affected versions: {{versions}}\n"
        "Attack vector: {{attack_vector}}\n"
        "\n"
        "--- Sigma ---\n"
        "{{sigma_rule}}\n"
        "--- KQL ---\n"
        "{{kql}}\n"
        "--- XQL ---\n"
        "{{xql}}\n"
        "--- AQK ---\n"
        "{{aqk}}\n"
        "--- EKQL ---\n"
        "{{ekql}}\n"
    ),
}

SAMPLE_CONTEXT = {
    "cve_id": "CVE-2024-1234",
    "vendor": "Red Hat",
    "product": "kernel",
    "product_type": "os",
    "versions": "el9 before 5.14.0-503",
    "summary": "A local user can escalate to root by abusing a kernel race.",
    "description": "A local user can escalate to root by abusing a kernel race.",
    "attack_vector": "LOCAL",
    "cwe_ids": "CWE-362",
    "severity": "HIGH",
    "priority": "P2",
    "cvss_score": "7.8",
    "epss_score": "0.12",
    "asset_name": "prod-rhel-01 (Red Hat / kernel / 9.4)",
    "asset_owner": "Alice",
    "email": "alice@corp.local",
    "username": "alice",
    "team": "Linux",
    "system_type": "linux",
    "version": "9.4",
    "sigma_rule": "title: CVE-2024-1234 hunt",
    "kql": "DeviceProcessEvents | where ...",
    "xql": "",
    "aqk": "",
    "ekql": "",
}


def template_path() -> Path:
    return Path(__file__).resolve().parents[2] / "data" / "mail_templates.json"


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        parts = [_stringify(item) for item in value]
        return ", ".join(part for part in parts if part)
    if isinstance(value, dict):
        try:
            return json.dumps(value, ensure_ascii=False)
        except TypeError:
            return str(value)
    return str(value).strip()


def flatten_ai_json(ai: Any) -> dict[str, str]:
    if not isinstance(ai, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in ai.items():
        name = str(key).strip()
        if not name:
            continue
        out[name] = _stringify(value)
    if out.get("summary") and not out.get("description"):
        out["description"] = out["summary"]
    if out.get("description") and not out.get("summary"):
        out["summary"] = out["description"]
    if out.get("versions") and not out.get("affected_versions"):
        out["affected_versions"] = out["versions"]
    return out


def render_template(template: str, context: dict[str, Any]) -> str:
    values = {str(key): _stringify(value) for key, value in (context or {}).items()}

    def replace(match: re.Match[str]) -> str:
        return values.get(match.group(1), "")

    return TOKEN_RE.sub(replace, template or "")


def load_templates() -> dict[str, str]:
    path = template_path()
    stored: dict[str, Any] = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                stored = loaded
        except (OSError, json.JSONDecodeError):
            stored = {}
    out = dict(DEFAULTS)
    for key in TEMPLATE_KEYS:
        value = stored.get(key)
        if isinstance(value, str) and value.strip():
            out[key] = value
    return out


def save_templates(payload: dict[str, Any]) -> dict[str, str]:
    current = load_templates()
    for key in TEMPLATE_KEYS:
        value = payload.get(key)
        if isinstance(value, str):
            current[key] = value
    path = template_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(current, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return current


def tokens_payload() -> list[dict[str, str]]:
    return [{"name": name, "token": f"{{{{{name}}}}}"} for name in CONTEXT_FIELDS]


def message_context(vuln: Any, payload: dict[str, Any] | None = None, detections: dict[str, str] | None = None) -> dict[str, str]:
    """Build {{token}} values: AI JSON first, then CVE fields, then the owner payload."""
    ctx: dict[str, str] = {}
    enrichment = getattr(vuln, "enrichment", None)
    ai = enrichment.get("ai") if isinstance(enrichment, dict) else None
    ctx.update(flatten_ai_json(ai))

    description = (getattr(vuln, "description", None) or "").strip() or "No operational summary is available yet."
    ctx.update(
        {
            "cve_id": _stringify(getattr(vuln, "cve_id", "")),
            "vendor": _stringify(getattr(vuln, "vendor", "")),
            "product": _stringify(getattr(vuln, "product", "")) or "unknown product",
            "product_type": _stringify(getattr(vuln, "product_type", "")),
            "versions": _stringify(getattr(vuln, "affected_versions", "")),
            "affected_versions": _stringify(getattr(vuln, "affected_versions", "")),
            "summary": _stringify(ctx.get("summary") or description),
            "description": description,
            "attack_vector": _stringify(getattr(vuln, "attack_vector", "")),
            "cwe_ids": _stringify(getattr(vuln, "cwe_ids", "")),
            "severity": _stringify(getattr(vuln, "severity", "")),
            "priority": _stringify(getattr(vuln, "priority", "")),
            "cvss_score": _stringify(getattr(vuln, "cvss_score", "")),
            "epss_score": _stringify(getattr(vuln, "epss_score", "")),
        }
    )
    for key, value in (payload or {}).items():
        ctx[str(key)] = _stringify(value)
    if payload:
        if payload.get("product"):
            ctx["product"] = _stringify(payload.get("product")) or ctx["product"]
        if payload.get("vendor"):
            ctx["vendor"] = _stringify(payload.get("vendor"))
        if not ctx.get("versions"):
            ctx["versions"] = _stringify(payload.get("version"))
    for key, value in (detections or {}).items():
        ctx[str(key)] = _stringify(value)
    if not ctx.get("summary"):
        ctx["summary"] = ctx.get("description", "")
    return ctx


def render_owner(vuln: Any, payload: dict[str, Any]) -> tuple[str, str]:
    templates = load_templates()
    ctx = message_context(vuln, payload)
    return (
        render_template(templates["owner_subject"], ctx).strip()[:200],
        render_template(templates["owner_body"], ctx),
    )


def render_hunt(vuln: Any, detections: dict[str, str] | None = None) -> tuple[str, str]:
    templates = load_templates()
    ctx = message_context(vuln, detections=detections)
    return (
        render_template(templates["hunt_subject"], ctx).strip()[:200],
        render_template(templates["hunt_body"], ctx),
    )
