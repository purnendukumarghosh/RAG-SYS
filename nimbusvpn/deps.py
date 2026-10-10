"""Shared FastAPI dependencies and helpers."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import segno
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session, sessionmaker

from nimbusvpn.config import Settings
from nimbusvpn.crypto import SecretBox
from nimbusvpn.db import AuditEvent, User
from nimbusvpn.security import SlidingWindowLimiter, TokenService
from nimbusvpn.wireguard import WireGuardManager

_bearer = HTTPBearer(auto_error=False)


@dataclass
class AppContext:
    settings: Settings
    session_factory: sessionmaker[Session]
    box: SecretBox
    tokens: TokenService
    wg: WireGuardManager
    login_limiter: SlidingWindowLimiter  # per client IP
    unknown_user_limiter: SlidingWindowLimiter  # mirrors account lockout for unknown names


def get_ctx(request: Request) -> AppContext:
    return request.app.state.ctx


def get_db(ctx: AppContext = Depends(get_ctx)) -> Iterator[Session]:
    session = ctx.session_factory()
    try:
        yield session
    finally:
        session.close()


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized
    claims = ctx.tokens.verify(credentials.credentials)
    if claims is None:
        raise unauthorized
    user = db.get(User, claims.user_id)
    if user is None or not user.enabled or user.token_version != claims.token_version:
        raise unauthorized
    return user


def admin_user(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin role required")
    return user


def audit(
    db: Session,
    request: Request | None,
    action: str,
    *,
    actor: User | None = None,
    target: str | None = None,
    **details: Any,
) -> None:
    """Queue an audit record on the session; it is persisted by the caller's commit."""
    db.add(
        AuditEvent(
            actor_id=actor.id if actor else None,
            actor=actor.username if actor else None,
            action=action,
            target=target,
            ip=client_ip(request) if request else None,
            details=json.dumps(details, default=str, sort_keys=True) if details else None,
        )
    )


def qr_svg_data_uri(payload: str) -> str:
    return segno.make(payload, error="m").svg_data_uri(scale=5, border=2, dark="#111827")
