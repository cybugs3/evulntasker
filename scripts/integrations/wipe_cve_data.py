#!/usr/bin/env python3
"""Wipe collected CVE data (keeps sources, assets, settings)."""

from __future__ import annotations

import json
import sys

import scripts.integrations._bootstrap  # noqa: F401
from app.db.session import SessionLocal
from app.services.wipe import wipe_collected_cve_data


def main() -> int:
    if "--yes" not in sys.argv:
        print("This deletes all ingested CVEs and pipeline history.", file=sys.stderr)
        print("Re-run with --yes to confirm.", file=sys.stderr)
        return 1
    db = SessionLocal()
    try:
        result = wipe_collected_cve_data(db)
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(f"Wipe failed: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
