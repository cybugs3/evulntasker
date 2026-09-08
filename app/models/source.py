"""Input sources: generic webhooks, API feeds, and Exchange mailbox listeners."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.types import JSONType


class InputSource(Base):
    __tablename__ = "input_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    source_type: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # webhook | api_feed | email | scheduled
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    ai_fallback_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Opaque per-source configuration (URL, mailbox, schedule, secret, etc.)
    config: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)

    webhook_token: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)

    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    events: Mapped[list["IngestEvent"]] = relationship(  # noqa: F821
        back_populates="source", cascade="all, delete-orphan"
    )
