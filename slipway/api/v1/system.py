from fastapi import APIRouter
from sqlalchemy import text

from slipway import __version__
from slipway.api.deps import DB

router = APIRouter(tags=["system"])


@router.get("/health")
async def health(db: DB) -> dict[str, object]:
    """Liveness/readiness probe for Docker and load balancers. No authentication."""
    await db.execute(text("SELECT 1"))
    return {"status": "ok", "version": __version__}
