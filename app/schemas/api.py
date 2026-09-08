"""Pydantic schemas for the JSON API consumed by the dashboard."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class SourceCreate(BaseModel):
    name: str
    source_type: str
    description: str = ""
    enabled: bool = True
    ai_fallback_enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)


class SourceUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    ai_fallback_enabled: bool | None = None
    config: dict[str, Any] | None = None


class SourceOut(ORMModel):
    id: int
    name: str
    source_type: str
    description: str
    enabled: bool
    ai_fallback_enabled: bool
    config: dict[str, Any]
    webhook_token: str | None
    last_event_at: datetime | None
    last_error: str | None
    event_count: int
    cve_count: int = 0


class IngestEventOut(ORMModel):
    id: int
    source_id: int
    status: str
    extracted_cves: list[Any]
    error: str | None
    received_at: datetime


class TicketOut(ORMModel):
    ticket_key: str
    ticket_type: str
    url: str
    status: str
    dry_run: bool
    assignee: str = ""


class MatchOut(ORMModel):
    confidence: float
    method: str
    asset_name: str = ""
    owner_email: str = ""
    team: str = ""


class AuditLogOut(ORMModel):
    id: int
    cve_id: str
    timestamp: datetime
    pipeline_step: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("pipeline_step", mode="before")
    @classmethod
    def _step_to_str(cls, value: Any) -> Any:
        if hasattr(value, "value"):
            return value.value
        return value


class VulnerabilityOut(ORMModel):
    id: int
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: float | None
    epss_score: float | None
    attack_vector: str | None
    vendor: str | None
    product: str | None
    pipeline_status: str
    status: str = "INGESTED"
    priority: str
    source_name: str | None
    ai_extraction_used: bool
    ai_enrichment_used: bool
    ai_matching_used: bool
    created_at: datetime
    tickets: list[TicketOut] = []

    @field_validator("status", mode="before")
    @classmethod
    def _status_to_str(cls, value: Any) -> Any:
        if hasattr(value, "value"):
            return value.value
        return value


class DashboardKpis(BaseModel):
    ingested_today: int
    pending_enrichment: int
    asset_matched: int
    jira_tasks_created: int
    completed: int
    failed: int
    critical_open: int
