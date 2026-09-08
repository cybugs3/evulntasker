"""Per-CVE audit trail for pipeline observability."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.enums import PipelineStatus, pipeline_status_enum
from app.models.types import JSONType


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utc_now,
        server_default=func.now(),
        nullable=False,
        index=True,
    )
    pipeline_step: Mapped[PipelineStatus] = mapped_column(
        pipeline_status_enum,
        nullable=False,
        index=True,
    )
    message: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)

    vulnerability: Mapped["Vulnerability"] = relationship(  # noqa: F821
        back_populates="audit_logs",
        primaryjoin="AuditLog.cve_id == Vulnerability.cve_id",
    )
