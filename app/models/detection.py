"""Detection artifacts generated for the Threat Hunting team."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class DetectionArtifact(Base):
    __tablename__ = "detection_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), nullable=False)

    sigma_rule: Mapped[str] = mapped_column(Text, default="")
    kql: Mapped[str] = mapped_column(Text, default="")  # Microsoft Sentinel / Defender
    xql: Mapped[str] = mapped_column(Text, default="")  # Palo Alto Cortex / XSIAM
    aqk: Mapped[str] = mapped_column(Text, default="")  # Azure Resource Graph / custom AQK
    ekql: Mapped[str] = mapped_column(Text, default="")  # Elastic Kibana Query Language

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="detections")  # noqa: F821
