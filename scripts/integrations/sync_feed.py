#!/usr/bin/env python3
"""Poll and ingest from a configured feed (local, smb, outlook, web-api)."""

from __future__ import annotations

import argparse
import sys

import scripts.integrations._bootstrap  # noqa: F401
from app.api.settings.common import get_or_create_source
from app.api.settings.feeds import pull_local_files, pull_outlook, pull_smb_files, pull_web_api
from app.db.session import SessionLocal


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync a EVulnTasker input feed")
    parser.add_argument("kind", choices=["local", "smb", "outlook", "web_api"], help="Feed type")
    args = parser.parse_args()
    db = SessionLocal()
    try:
        source = get_or_create_source(db, args.kind)
        if not source.enabled:
            print(f"{args.kind} feed is disabled in settings.", file=sys.stderr)
            return 1
        pullers = {
            "local": pull_local_files,
            "smb": pull_smb_files,
            "outlook": pull_outlook,
            "web_api": pull_web_api,
        }
        count = pullers[args.kind](db, source)
        print(f"Ingested {count} item(s) from {args.kind}")
        return 0
    except Exception as exc:
        print(f"Sync failed: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
