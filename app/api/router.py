from fastapi import APIRouter

from app.api import dashboard, debug, inventory, pipeline, repositories, settings, sources, vulnerabilities, webhooks

api_router = APIRouter(prefix="/api")
api_router.include_router(dashboard.router, tags=["dashboard"])
api_router.include_router(debug.router, tags=["debug"])
api_router.include_router(inventory.router, tags=["inventory"])
api_router.include_router(pipeline.router, tags=["pipeline"])
api_router.include_router(sources.router, tags=["sources"])
api_router.include_router(repositories.router, tags=["repositories"])
api_router.include_router(vulnerabilities.router, tags=["vulnerabilities"])
api_router.include_router(webhooks.router, tags=["webhooks"])
api_router.include_router(settings.router, tags=["settings"])
