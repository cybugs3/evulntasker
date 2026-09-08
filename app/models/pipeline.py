"""Ingest events and per-CVE pipeline run history (audit trail)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.types import JSONType


class IngestEvent(Base):
    __tablename__ = "ingest_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("input_sources.id"), nullable=False)
    payload: Mapped[dict[str, Any] | str] = mapped_column(JSONType, default=dict)
    raw_text: Mapped[str] = mapped_column(Text, default="")
    content_type: Mapped[str] = mapped_column(String(64), default="application/json")
    status: Mapped[str] = mapped_column(String(32), default="queued")  # queued|processing|done|failed
    extracted_cves: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    source: Mapped["InputSource"] = relationship(back_populates="events")  # noqa: F821
    runs: Mapped[list["PipelineRun"]] = relationship(back_populates="event")


class PipelineRun(Base):
    __tablename__ = "pipeline_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vulnerability_id: Mapped[int | None] = mapped_column(
        ForeignKey("vulnerabilities.id"), nullable=True
    )
    event_id: Mapped[int | None] = mapped_column(ForeignKey("ingest_events.id"), nullable=True)

    current_step: Mapped[str] = mapped_column(String(32), default="ingest")
    status: Mapped[str] = mapped_column(String(32), default="running")
    log: Mapped[list[Any]] = mapped_column(JSONType, default=list)

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="runs")  # noqa: F821
    event: Mapped[IngestEvent | None] = relationship(back_populates="runs")
