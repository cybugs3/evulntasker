"""Backward-compatible Jira client wrapper."""

from app.integrations.ticketing.jira import JiraTicketingClient as JiraClient

__all__ = ["JiraClient"]
