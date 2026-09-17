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
    ranked_repositories,
    repository_cve_counts,
    sync_source_repositories,
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
    cve_count: int = 0
    last_error: str | None
    notes: str

    model_config = {"from_attributes": True}


@router.get("/repositories", response_model=list[RepositoryOut])
def list_repositories(db: Session = Depends(get_db)) -> list[RepositoryOut]:
    purge_placeholder_repos(db)
    ensure_atom_feeds(db)
    sync_source_repositories(db)
    rows = ranked_repositories(db.query(VulnerabilityRepository).all())
    counts = repository_cve_counts(db, rows)
    return [
        RepositoryOut.model_validate(row).model_copy(update={"cve_count": counts.get(row.id, 0)})
        for row in rows
    ]


@router.post("/repositories/{repo_id}/sync", response_model=RepositoryOut)
def sync_repository(repo_id: int, db: Session = Depends(get_db)) -> VulnerabilityRepository:
    repo = db.get(VulnerabilityRepository, repo_id)
    if not repo:
        raise HTTPException(404, "Repository not found")
    cfg = repo.config if isinstance(repo.config, dict) else {}
    if cfg.get("source_managed"):
        from app.models.source import InputSource

        source = db.get(InputSource, cfg.get("source_id"))
        if source is None:
            raise HTTPException(404, "Source not found")
        kind = repo.feed_type
        try:
            if kind == "local":
                from app.api.settings.feeds import pull_local_files

                pull_local_files(db, source)
            elif kind == "smb":
                from app.api.settings.feeds import pull_smb_files

                pull_smb_files(db, source)
            elif kind == "outlook":
                from app.api.settings.feeds import pull_outlook

                pull_outlook(db, source)
            elif kind == "inline":
                raise HTTPException(400, "Enter a CVE ID on Input Sources.")
            else:
                raise HTTPException(400, "This repository cannot sync from here.")
        except ValueError as exc:
            raise HTTPException(400, f"Sync failed: {exc}") from exc
        sync_source_repositories(db)
        db.refresh(repo)
        return repo
    if repo.feed_type == ATOM_TYPE:
        from app.api.settings.feeds import pull_web_api

        source = atom_source(db)
        if source is None or not (source.config or {}):
            raise HTTPException(400, "Configure ATOM feeds in Settings → Feeds first.")
        try:
            pull_web_api(db, source, only_url=repo.endpoint, include_disabled=True)
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
    cfg = repo.config if isinstance(repo.config, dict) else {}
    if cfg.get("source_managed"):
        from app.models.source import InputSource

        source = db.get(InputSource, cfg.get("source_id"))
        if source is None:
            raise HTTPException(404, "Source not found")
        source.enabled = not source.enabled
        if not source.enabled:
            source.last_error = None
        db.commit()
        sync_source_repositories(db)
        db.refresh(repo)
        return repo
    repo.enabled = not repo.enabled
    from app.services.repo_catalog import sync_atom_channel_enabled

    if repo.feed_type == ATOM_TYPE:
        sync_atom_channel_enabled(db)
    db.commit()
    db.refresh(repo)
    return repo
