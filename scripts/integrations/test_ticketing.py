#!/usr/bin/env python3
"""Test ticketing provider connectivity (Jira / Monday / custom CRM)."""

from __future__ import annotations

import asyncio
import json
import sys

import httpx
import scripts.integrations._bootstrap  # noqa: F401
from app.config import enabled_ticketing_providers, get_settings
from app.utils.integration_connection import probe_connection


async def main() -> int:
    settings = get_settings()
    enabled = enabled_ticketing_providers(settings)
    provider = enabled[0] if enabled else (settings.ticketing_provider or "jira").lower()
    conn = settings.ticketing_connection
    print(f"Ticketing providers on: {enabled or '(none)'}")
    print(f"Testing: {provider}")
    print(f"Base URL: {conn.base_url or '(not configured)'}")
    if not enabled:
        print("Enable a ticketing provider in Settings first.", file=sys.stderr)
        return 1
    try:
        if provider == "jira":
            result = await probe_connection(conn, "/rest/api/3/myself")
        elif provider == "monday":
            token = settings.ticketing_password or settings.jira_api_token
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.post(
                    "https://api.monday.com/v2",
                    json={"query": "{ me { id name } }"},
                    headers={"Authorization": token, "Content-Type": "application/json"},
                )
                response.raise_for_status()
                result = {"ok": True, "status": response.status_code, "body": response.json()}
        else:
            result = await probe_connection(conn, settings.custom_ticketing_api_path or "/")
        print("Result:", json.dumps(result, indent=2, default=str))
    except Exception as exc:
        print(f"Ticketing test failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
