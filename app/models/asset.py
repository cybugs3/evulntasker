"""Organizational assets (CMDB / Sonatype) and CVE-to-asset matches."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    vendor: Mapped[str] = mapped_column(String(128), default="", index=True)
    product: Mapped[str] = mapped_column(String(128), default="", index=True)
    version: Mapped[str] = mapped_column(String(64), default="")
    system_type: Mapped[str] = mapped_column(String(64), default="application")

    owner_name: Mapped[str] = mapped_column(String(128), default="")
    owner_username: Mapped[str] = mapped_column(String(64), default="")
    owner_email: Mapped[str] = mapped_column(String(256), default="")
    team: Mapped[str] = mapped_column(String(128), default="")

    cmdb_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sonatype_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    environment: Mapped[str] = mapped_column(String(32), default="production")
    notes: Mapped[str] = mapped_column(Text, default="")

    source: Mapped[str] = mapped_column(String(32), default="local", index=True)
    external_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1")
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    matches: Mapped[list["AssetMatch"]] = relationship(back_populates="asset")


class AssetMatch(Base):
    __tablename__ = "asset_matches"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "asset_id", name="uq_vuln_asset"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), nullable=False)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    method: Mapped[str] = mapped_column(String(32), default="local")  # csv | cmdb | sonatype | itnm | local | ai

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="matches")  # noqa: F821
    asset: Mapped[Asset] = relationship(back_populates="matches")
