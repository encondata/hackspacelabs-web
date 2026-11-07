"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Text, column, select, table
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.exceptions import HTTPException as StarletteHTTPException

from kiln import __version__
from kiln.api.v1 import api_router
from kiln.core.config import get_settings
from kiln.core.crypto import DecryptionError, decrypt, encrypted_columns
from kiln.db.base import Base
from kiln.db.session import dispose_engine, get_sessionmaker, init_engine
from kiln.services.deployer import runner
from kiln.services.hosts import poll_hosts_forever
from kiln.services.users import bootstrap
from kiln.web import oauth, pages

log = logging.getLogger("kiln")
STATIC_DIR = Path(__file__).parent / "web" / "static"

CSP = (
    "default-src 'self'; img-src 'self' data: https://avatars.githubusercontent.com; "
    "style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self' https://github.com"
)


async def check_encryption_key(db: AsyncSession) -> bool:
    """Try one stored secret per encrypted column so a wrong KILN_ENCRYPTION_KEY is reported at startup."""
    for source, col in encrypted_columns(Base.metadata):
        raw = table(source.name, column(col.name, Text())).c[col.name]
        token = await db.scalar(select(raw).where(raw.is_not(None)).limit(1))
        if token is None:
            continue
        try:
            decrypt(token)
        except DecryptionError:
            log.error(
                "KILN_ENCRYPTION_KEY cannot decrypt stored secrets (tried %s.%s), so they read as empty. "
                "Add the old key after the new one (comma-separated) and run `kiln rotate-encryption-key`, "
                "or re-enter the secrets.",
                source.name, col.name,
            )
            return False
    return True


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    init_engine()
    async with get_sessionmaker()() as db:
        await bootstrap(db)
        await check_encryption_key(db)
    await runner.recover_interrupted()
    poller = asyncio.create_task(poll_hosts_forever(), name="host-poller")
    log.info("Kiln %s started (%s)", __version__, get_settings().env)
    try:
        yield
    finally:
        poller.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await poller
        await runner.shutdown()
        await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    app = FastAPI(
        title="Kiln",
        version=__version__,
        description="Deploy GitHub repositories to your own Docker hosts over SSH.",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        if not request.url.path.startswith("/api/docs"):
            response.headers.setdefault("Content-Security-Policy", CSP)
        if settings.secure_cookies:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        return response

    @app.exception_handler(pages.LoginRequired)
    async def login_required(request: Request, exc: pages.LoginRequired) -> Response:
        return RedirectResponse(f"/login?next={quote(exc.next_url)}", status_code=302)

    @app.exception_handler(pages.PageForbidden)
    async def page_forbidden(request: Request, exc: pages.PageForbidden) -> Response:
        async with get_sessionmaker()() as db:
            return await pages.render(
                request, db, "error.html", getattr(request.state, "auth", None), status_code=403, code=403,
                message=f"You don't have permission to view this page ({exc.permission}). Ask an admin for access.",
            )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> Response:
        # Malformed ids in page URLs get the friendly 404 page; the API keeps FastAPI's 422 detail.
        if not request.url.path.startswith("/api/") and "text/html" in request.headers.get("accept", ""):
            async with get_sessionmaker()() as db:
                return await pages.not_found_page(request, db, getattr(request.state, "auth", None))
        return await request_validation_exception_handler(request, exc)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        wants_html = "text/html" in request.headers.get("accept", "") and not request.url.path.startswith("/api/")
        if wants_html and exc.status_code in (404, 405):
            async with get_sessionmaker()() as db:
                return await pages.not_found_page(request, db, getattr(request.state, "auth", None))
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(api_router, prefix="/api/v1")
    app.include_router(oauth.router)
    app.include_router(pages.router)
    return app


app = create_app()
