"""
Targeted LLM / AI Co-pilot.

Extraction: used only when regex finds no CVE ID.
Enrichment: rewrites the CVE into plain language for Jira tickets and fills
missing structured fields. The model must return a strict JSON object.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from app.config import get_settings

log = logging.getLogger(__name__)

EXTRACT_SCHEMA_HINT = {
    "cve_ids": ["CVE-YYYY-NNNN"],
    "vendor": "string or null",
    "product": "string or null",
    "product_type": "application|os|library|firmware|null",
    "versions": "string or null",
    "summary": "one paragraph",
}

ENRICH_SCHEMA_HINT = {
    "vendor": "manufacturer / vendor name",
    "product": "product name",
    "product_type": "os|application|library|firmware",
    "versions": "human-readable affected version range",
    "attack_vector": "NETWORK|ADJACENT|LOCAL|PHYSICAL",
    "cwe_ids": ["CWE-nnn"],
    "summary": (
        "2-4 short paragraphs in plain English: what the component is, what an "
        "attacker can do, the practical impact, and what the owner should do. "
        "This text is placed into the notification template as {{summary}} / {{description}}."
    ),
}

OWNERSHIP_SCHEMA_HINT = {
    "owner_name": "string",
    "owner_username": "string",
    "owner_email": "string",
    "team": "string",
    "rationale": "string",
}


class AICopilot:
    def __init__(self) -> None:
        self.settings = get_settings()

    @property
    def available(self) -> bool:
        return self.settings.ai_configured

    async def extract(self, text: str) -> dict[str, Any]:
        """Extract CVE / vendor / product from unstructured text."""
        return await self._complete(
            system=(
                "You extract vulnerability identifiers from security advisories. "
                "Return ONLY valid JSON matching the schema. If a field is unknown, use null."
            ),
            user=f"Schema: {json.dumps(EXTRACT_SCHEMA_HINT)}\n\nText:\n{text[:8000]}",
            fallback={"cve_ids": [], "vendor": None, "product": None, "product_type": None,
                      "versions": None, "summary": None},
        )

    async def enrich(self, cve_id: str, partial: dict[str, Any]) -> dict[str, Any]:
        """Identify vendor/product/type/versions and rewrite the description."""
        known = dict(partial or {})
        inventory = known.pop("inventory", [])
        fallback = {k: v for k, v in known.items() if k != "summary"}
        return await self._complete(
            system=(
                "You are a vulnerability intelligence analyst. Return ONLY a JSON object. "
                "Use internet knowledge plus the Known fields (NVD/EPSS) to identify: "
                "vendor (manufacturer), product, product_type, versions (affected range), "
                "and summary (clear operational description). "
                "Those JSON keys are inserted into an email template as {{vendor}}, "
                "{{product}}, {{product_type}}, {{versions}}, {{summary}}. "
                "Always write `summary` in plain language for the asset owner. "
                "Cover: (1) what product/component is affected, (2) who can exploit it "
                "and how, (3) what happens if it succeeds, (4) what the owner should do. "
                "If inventory lists related products, say the CVE is likely relevant. "
                "Do not claim a confirmed asset match. Do not invent CVSS scores. "
                "If you are unsure of a field, use null instead of guessing."
            ),
            user=(
                f"Schema: {json.dumps(ENRICH_SCHEMA_HINT)}\n"
                f"CVE: {cve_id}\n"
                f"Known: {json.dumps(known)}\n"
                f"Inventory: {json.dumps(inventory[:25])}"
            ),
            fallback=fallback,
        )

    async def infer_ownership(
        self, vendor: str | None, product: str | None, assets_summary: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Guess the most likely owning team from historical/local asset inventory."""
        return await self._complete(
            system=(
                "You map a vendor/product to the most likely asset owner from the inventory. "
                "Return ONLY valid JSON. If unsure, pick the closest team and lower confidence."
            ),
            user=(
                f"Schema: {json.dumps(OWNERSHIP_SCHEMA_HINT)}\n"
                f"Vendor: {vendor}\nProduct: {product}\nInventory: {json.dumps(assets_summary[:50])}"
            ),
            fallback={
                "owner_name": "Unassigned",
                "owner_username": "security-ops",
                "owner_email": "soc@example.com",
                "team": "Security Operations",
                "rationale": "AI fallback unavailable; defaulted to SOC.",
            },
        )

    async def _complete(self, system: str, user: str, fallback: dict[str, Any]) -> dict[str, Any]:
        if not self.available:
            log.info("AI copilot not configured; returning fallback JSON")
            return fallback

        url = self.settings.ai_api_base.rstrip("/") + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.settings.ai_api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": self.settings.ai_model,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            async with httpx.AsyncClient(timeout=45.0) as client:
                response = await client.post(url, headers=headers, json=body)
                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"]
                return json.loads(content)
        except Exception:
            log.exception("AI copilot call failed; using fallback")
            return fallback
