"""Shared enumerations for pipeline observability."""

from __future__ import annotations

import enum

from sqlalchemy import Enum as SAEnum


class PipelineStatus(str, enum.Enum):
    """Lifecycle of a CVE as it moves through the five pipeline steps."""

    INGESTED = "INGESTED"
    EXTRACTED = "EXTRACTED"
    ENRICHED = "ENRICHED"
    MATCHED = "MATCHED"
    ACTIONED = "ACTIONED"
    AI_FALLBACK = "AI_FALLBACK"
    FAILED = "FAILED"


# VARCHAR on SQLite and PostgreSQL so Alembic does not need a native PG ENUM.
pipeline_status_enum = SAEnum(
    PipelineStatus,
    name="pipeline_status",
    native_enum=False,
    length=32,
    values_callable=lambda enum_cls: [member.value for member in enum_cls],
    validate_strings=True,
)
