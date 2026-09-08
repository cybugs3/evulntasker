#!/usr/bin/env python3
"""Run the CVE pipeline for a single ingest event ID."""

from __future__ import annotations

import argparse
import asyncio
import sys

import scripts.integrations._bootstrap  # noqa: F401
from app.db.session import SessionLocal
from app.pipeline.orchestrator import PipelineOrchestrator


async def main() -> int:
    parser = argparse.ArgumentParser(description="Process one ingest event through the pipeline")
    parser.add_argument("event_id", type=int, help="Ingest event database ID")
    args = parser.parse_args()
    db = SessionLocal()
    try:
        await PipelineOrchestrator(db).run_event(args.event_id)
        print(f"Pipeline finished for event {args.event_id}")
        return 0
    except Exception as exc:
        print(f"Pipeline failed: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
