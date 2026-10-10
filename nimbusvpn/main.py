"""Application factory: wires configuration, storage, WireGuard and the HTTP API together."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select

from nimbusvpn import __version__
from nimbusvpn.api import admin, auth, devices
from nimbusvpn.config import Settings
from nimbusvpn.crypto import SecretBox
from nimbusvpn.db import User, init_db, make_engine, make_session_factory
from nimbusvpn.deps import AppContext
from nimbusvpn.security import SlidingWindowLimiter, TokenService, hash_password, password_problems
from nimbusvpn.wireguard import (
    WireGuardBackend,
    WireGuardManager,
    load_or_create_server_keys,
    make_backend,
)

log = logging.getLogger("nimbusvpn")
STATIC_DIR = Path(__file__).parent / "static"

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def bootstrap_admin(settings: Settings, ctx: AppContext) -> None:
    """Create the first admin from NIMBUS_ADMIN_USERNAME/PASSWORD when no users exist."""
    with ctx.session_factory() as db:
        if db.scalar(select(func.count()).select_from(User)):
            return
        if not (settings.admin_username and settings.admin_password):
            log.warning(
                "no users exist - set NIMBUS_ADMIN_USERNAME/NIMBUS_ADMIN_PASSWORD "
                "or run `python -m nimbusvpn create-admin`"
            )
            return
        username = settings.admin_username.strip().lower()
        problems = password_problems(
            settings.admin_password, username, settings.min_password_length
        )
        if problems:
            raise ValueError("NIMBUS_ADMIN_PASSWORD " + "; ".join(problems))
        db.add(
            User(
                username=username,
                password_hash=hash_password(settings.admin_password),
                role="admin",
            )
        )
        db.commit()
        log.info("created bootstrap admin %r", username)


async def reconcile_loop(ctx: AppContext) -> None:
    """Periodically converge WireGuard with the database (expiries, crashed syncs, drift)."""
    interval = ctx.settings.reconcile_interval_seconds
    while True:
        await asyncio.sleep(interval)
        await asyncio.to_thread(ctx.wg.sync)


def build_context(settings: Settings, backend: WireGuardBackend | None = None) -> AppContext:
    # Everything this process creates (database, key files) is private to its user.
    os.umask(0o077)
    settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    with contextlib.suppress(OSError):
        settings.data_dir.chmod(0o700)
    engine = make_engine(settings.resolved_database_url)
    init_db(engine)
    session_factory = make_session_factory(engine)
    box = SecretBox(settings.secret_key)
    server_keys = load_or_create_server_keys(settings, box)
    wg = WireGuardManager(
        settings, backend or make_backend(settings), box, session_factory, server_keys
    )
    return AppContext(
        settings=settings,
        session_factory=session_factory,
        box=box,
        tokens=TokenService(settings.secret_key, settings.access_token_ttl_minutes),
        wg=wg,
        login_limiter=SlidingWindowLimiter(
            settings.login_ip_limit_per_window, settings.login_ip_window_seconds
        ),
        unknown_user_limiter=SlidingWindowLimiter(
            settings.login_max_attempts, settings.login_lockout_minutes * 60
        ),
    )


def create_app(
    settings: Settings | None = None, backend: WireGuardBackend | None = None
) -> FastAPI:
    settings = settings or Settings()
    ctx = build_context(settings, backend)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        bootstrap_admin(settings, ctx)
        if not ctx.wg.sync():
            log.error("initial WireGuard sync failed; retrying in the background")
        task = None
        if settings.reconcile_interval_seconds > 0:
            task = asyncio.create_task(reconcile_loop(ctx))
        yield
        if task:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    docs = settings.enable_api_docs
    app = FastAPI(
        title="NimbusVPN",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs" if docs else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if docs else None,
    )
    app.state.ctx = ctx

    @app.middleware("http")
    async def security_headers(request: Request, call_next) -> Response:
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/health", tags=["health"])
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    app.include_router(auth.router)
    app.include_router(devices.router)
    app.include_router(admin.router)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    return app
