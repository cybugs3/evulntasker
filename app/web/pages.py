"""HTML page routes. JSON APIs live under app.api."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app import __app_name__, __tagline__, __version__, __version_label__

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

router = APIRouter()


def render_page(request: Request, template: str, **extra) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name=template,
        context={
            "app_name": __app_name__,
            "version": __version__,
            "version_label": __version_label__,
            "tagline": __tagline__,
            **extra,
        },
    )


@router.get("/static/img/evulntasker-icon.png")
def evulntasker_icon() -> FileResponse:
    static_icon = BASE_DIR / "static" / "img" / "evulntasker-icon.png"
    root_icon = BASE_DIR.parent.parent / "EVulnTasker-ICON.png"
    for path in (static_icon, root_icon):
        if path.is_file():
            return FileResponse(path, media_type="image/png")
    return FileResponse(root_icon, media_type="image/png")


@router.get("/", response_class=HTMLResponse)
def dashboard_page(request: Request) -> HTMLResponse:
    return render_page(request, "dashboard.html", active="dashboard")


@router.get("/trends", response_class=HTMLResponse)
def trends_page(request: Request) -> HTMLResponse:
    return render_page(request, "trends.html", active="trends")


@router.get("/workflow", response_class=HTMLResponse)
def workflow_page(request: Request) -> HTMLResponse:
    return render_page(request, "workflow.html", active="workflow")


@router.get("/status", response_class=HTMLResponse)
def status_page(request: Request) -> HTMLResponse:
    return render_page(request, "status.html", active="status")


@router.get("/sources", response_class=HTMLResponse)
def sources_page(request: Request) -> HTMLResponse:
    return render_page(request, "sources.html", active="sources")


@router.get("/extraction", response_class=HTMLResponse)
def extraction_page(request: Request) -> HTMLResponse:
    return render_page(request, "extraction.html", active="extraction")


@router.get("/enrichment", response_class=HTMLResponse)
def enrichment_page(request: Request) -> HTMLResponse:
    return render_page(request, "enrichment.html", active="enrichment")


@router.get("/debug", response_class=HTMLResponse)
def debug_page(request: Request) -> HTMLResponse:
    return render_page(request, "debug.html", active="debug")


@router.get("/inventory", response_class=HTMLResponse)
def inventory_page(request: Request) -> HTMLResponse:
    return render_page(request, "inventory.html", active="inventory")


@router.get("/cves", response_class=HTMLResponse)
def cves_page(request: Request) -> HTMLResponse:
    return render_page(request, "cves.html", active="cves")


@router.get("/matching", response_class=HTMLResponse)
def matching_page(request: Request) -> HTMLResponse:
    return render_page(request, "matching.html", active="matching")


@router.get("/actions", response_class=HTMLResponse)
def actions_page(request: Request) -> HTMLResponse:
    return render_page(request, "actions.html", active="actions")


@router.get("/feeds", response_class=HTMLResponse)
def feeds_page(request: Request) -> HTMLResponse:
    return render_page(request, "sources.html", active="sources")


@router.get("/repositories")
def repositories_page() -> RedirectResponse:
    return RedirectResponse("/sources", status_code=301)


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request) -> HTMLResponse:
    return render_page(request, "settings.html", active="settings")


@router.get("/tracker")
def tracker_page() -> RedirectResponse:
    return RedirectResponse("/cves", status_code=301)


@router.get("/vulnerabilities/{cve_id}", response_class=HTMLResponse)
def vulnerability_page(request: Request, cve_id: str) -> HTMLResponse:
    return render_page(request, "vulnerability.html", active="status", cve_id=cve_id.upper())
