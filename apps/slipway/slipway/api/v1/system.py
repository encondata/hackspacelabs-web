from fastapi import APIRouter
from sqlalchemy import text

from slipway import __version__
from slipway.api.deps import DB, Auth
from slipway.core.config import get_settings

router = APIRouter(tags=["system"])


@router.get("/health")
async def health(db: DB) -> dict[str, object]:
    """Liveness/readiness probe for Docker and load balancers. No authentication."""
    await db.execute(text("SELECT 1"))
    return {"status": "ok", "version": __version__}


@router.get("/system/info")
async def info(ctx: Auth) -> dict[str, object]:
    """What the portal UI needs to know about this Slipway: version and which optional features are set up."""
    s = get_settings()
    return {
        "version": __version__,
        "github_enabled": s.github_enabled,
        "github_service_token": bool(s.github_service_token),
        "host_poll_interval": s.host_poll_interval,
        "default_deploy_root": s.default_deploy_root,
    }
