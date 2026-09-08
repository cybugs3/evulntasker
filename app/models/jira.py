"""Jira tickets opened by the pipeline (owner task + threat-hunting task)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class JiraTicket(Base):
    __tablename__ = "jira_tickets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), nullable=False)
    ticket_key: Mapped[str] = mapped_column(String(32), index=True)
    ticket_type: Mapped[str] = mapped_column(String(32), nullable=False)  # owner | threat_hunt
    url: Mapped[str] = mapped_column(String(512), default="")
    status: Mapped[str] = mapped_column(String(32), default="Open")
    assignee: Mapped[str] = mapped_column(String(128), default="")
    summary: Mapped[str] = mapped_column(String(512), default="")
    dry_run: Mapped[bool] = mapped_column(default=False)
    raw_response: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="tickets")  # noqa: F821
