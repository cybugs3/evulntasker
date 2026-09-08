#!/usr/bin/env python3
"""Test Sonatype / Nexus connectivity using settings from .env."""

from __future__ import annotations

import asyncio
import json
import sys

import scripts.integrations._bootstrap  # noqa: F401
from app.config import get_settings
from app.integrations.sonatype import SonatypeClient
from app.utils.integration_connection import probe_connection


async def main() -> int:
    settings = get_settings()
    conn = settings.sonatype_connection
    print(f"Sonatype enabled: {conn.enabled}")
    print(f"Base URL: {conn.base_url or '(not configured)'}")
    if not conn.base_url:
        print("Set SONATYPE_HOST (or SONATYPE_API_URL) in .env first.", file=sys.stderr)
        return 1
    try:
        probe = await probe_connection(conn, "/api/v2/applications")
        print("Probe:", json.dumps(probe, indent=2))
    except Exception as exc:
        print(f"Probe failed: {exc}", file=sys.stderr)
        return 1
    rows = await SonatypeClient().find("apache", "log4j")
    print(f"Sample lookup returned {len(rows)} row(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
