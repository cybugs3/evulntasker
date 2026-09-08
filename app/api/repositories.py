from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.repository import VulnerabilityRepository
from app.services.repo_catalog import (
    ATOM_TYPE,
    atom_source,
    ensure_atom_feeds,
    purge_placeholder_repos,
)

router = APIRouter()


class RepositoryOut(BaseModel):
    id: int
    name: str
    feed_type: str
    endpoint: str
    enabled: bool
    sync_status: str
    last_sync_at: datetime | None
    raw_count: int
    last_error: str | None
    notes: str

    model_config = {"from_attributes": True}


@router.get("/repositories", response_model=list[RepositoryOut])
def list_repositories(db: Session = Depends(get_db)) -> list[VulnerabilityRepository]:
    purge_placeholder_repos(db)
    ensure_atom_feeds(db)
    return db.query(VulnerabilityRepository).order_by(VulnerabilityRepository.id).all()


@router.post("/repositories/{repo_id}/sync", response_model=RepositoryOut)
def sync_repository(repo_id: int, db: Session = Depends(get_db)) -> VulnerabilityRepository:
    repo = db.get(VulnerabilityRepository, repo_id)
    if not repo:
        raise HTTPException(404, "Repository not found")
    if repo.feed_type == ATOM_TYPE:
        from app.api.settings.feeds import pull_web_api

        source = atom_source(db)
        if source is None or not (source.config or {}):
            raise HTTPException(400, "Configure ATOM feeds in Settings → Feeds first.")
        if not source.enabled:
            raise HTTPException(409, "ATOM feeds are disabled in Settings → Feeds.")
        if not repo.enabled:
            raise HTTPException(409, "This feed is paused. Enable it first.")
        try:
            pull_web_api(db, source, only_url=repo.endpoint)
        except ValueError as exc:
            raise HTTPException(400, f"Sync failed: {exc}") from exc
        db.refresh(repo)
        return repo
    repo.sync_status = "ok"
    repo.last_sync_at = datetime.now(timezone.utc)
    repo.last_error = None
    db.commit()
    db.refresh(repo)
    return repo


@router.post("/repositories/{repo_id}/toggle", response_model=RepositoryOut)
def toggle_repository(repo_id: int, db: Session = Depends(get_db)) -> VulnerabilityRepository:
    repo = db.get(VulnerabilityRepository, repo_id)
    if not repo:
        raise HTTPException(404, "Repository not found")
    repo.enabled = not repo.enabled
    db.commit()
    db.refresh(repo)
    return repo
