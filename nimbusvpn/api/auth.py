"""Authentication endpoints: login, logout, password and two-factor management."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from nimbusvpn.db import User, utcnow
from nimbusvpn.deps import (
    AppContext,
    audit,
    client_ip,
    current_user,
    get_ctx,
    get_db,
    qr_svg_data_uri,
)
from nimbusvpn.schemas import (
    LoginRequest,
    PasswordChange,
    TokenResponse,
    TotpCode,
    TotpDisable,
    TotpSetupResponse,
    UserOut,
)
from nimbusvpn.security import (
    hash_password,
    needs_rehash,
    new_totp_secret,
    password_problems,
    totp_provisioning_uri,
    verify_password,
    verify_totp,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

INVALID_CREDENTIALS = "invalid username or password"
LOCKED = "too many failed attempts - try again later"


def totp_context(user: User) -> str:
    return f"totp:{user.id}"


def issue_token(ctx: AppContext, user: User) -> TokenResponse:
    return TokenResponse(
        access_token=ctx.tokens.issue(user.id, user.token_version),
        expires_in=int(ctx.tokens.ttl.total_seconds()),
        user=UserOut.model_validate(user),
    )


def _register_failure(ctx: AppContext, db: Session, request: Request, user: User, reason: str):
    user.failed_logins += 1
    locked = user.failed_logins >= ctx.settings.login_max_attempts
    if locked:
        user.locked_until = utcnow() + timedelta(minutes=ctx.settings.login_lockout_minutes)
        user.failed_logins = 0
    audit(db, request, "login.failed", target=user.username, reason=reason, locked=locked)
    db.commit()


@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest,
    request: Request,
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> TokenResponse:
    if not ctx.login_limiter.hit(f"ip:{client_ip(request)}"):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, LOCKED)

    username = body.username.strip().lower()
    user = db.scalar(select(User).where(User.username == username))

    if user is None:
        # Same work and the same answers as for a real account, so probing cannot tell
        # which usernames exist - including the lockout after repeated failures.
        verify_password(None, body.password)
        if not ctx.unknown_user_limiter.hit(username):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, LOCKED)
        audit(db, request, "login.failed", target=username[:128], reason="unknown user")
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_CREDENTIALS)

    if user.locked_until and user.locked_until > utcnow():
        verify_password(None, body.password)
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, LOCKED)

    if not verify_password(user.password_hash, body.password):
        _register_failure(ctx, db, request, user, "bad password")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_CREDENTIALS)

    if not user.enabled:
        audit(db, request, "login.failed", target=user.username, reason="account disabled")
        db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "account disabled")

    if user.totp_enabled:
        if not body.totp_code:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "totp_required")
        secret = ctx.box.decrypt(user.totp_secret_enc or "", totp_context(user))
        step = verify_totp(secret, body.totp_code, user.totp_last_step)
        if step is None:
            _register_failure(ctx, db, request, user, "bad totp code")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid two-factor code")
        user.totp_last_step = step

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    audit(db, request, "login.success", actor=user, target=user.username)
    db.commit()
    return issue_token(ctx, user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Revoke every token issued to this user (all sessions)."""
    user.token_version += 1
    audit(db, request, "logout", actor=user, target=user.username)
    db.commit()


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)) -> User:
    return user


@router.post("/password", response_model=TokenResponse)
def change_password(
    body: PasswordChange,
    request: Request,
    user: User = Depends(current_user),
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> TokenResponse:
    if not verify_password(user.password_hash, body.current_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "current password is incorrect")
    problems = password_problems(body.new_password, user.username, ctx.settings.min_password_length)
    if problems:
        raise HTTPException(422, "password " + "; ".join(problems))
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1  # sign out every other session
    audit(db, request, "password.change", actor=user, target=user.username)
    db.commit()
    return issue_token(ctx, user)


@router.post("/totp/setup", response_model=TotpSetupResponse)
def totp_setup(
    request: Request,
    user: User = Depends(current_user),
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> TotpSetupResponse:
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "two-factor authentication is already on")
    secret = new_totp_secret()
    user.totp_secret_enc = ctx.box.encrypt(secret, totp_context(user))
    db.commit()
    uri = totp_provisioning_uri(secret, user.username)
    return TotpSetupResponse(secret=secret, otpauth_uri=uri, qr_svg=qr_svg_data_uri(uri))


@router.post("/totp/enable", response_model=UserOut)
def totp_enable(
    body: TotpCode,
    request: Request,
    user: User = Depends(current_user),
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> User:
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "two-factor authentication is already on")
    if not user.totp_secret_enc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "call /api/auth/totp/setup first")
    secret = ctx.box.decrypt(user.totp_secret_enc, totp_context(user))
    step = verify_totp(secret, body.code, user.totp_last_step)
    if step is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid two-factor code")
    user.totp_enabled = True
    user.totp_last_step = step
    audit(db, request, "totp.enable", actor=user, target=user.username)
    db.commit()
    return user


@router.post("/totp/disable", response_model=UserOut)
def totp_disable(
    body: TotpDisable,
    request: Request,
    user: User = Depends(current_user),
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> User:
    if not user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "two-factor authentication is not on")
    if not verify_password(user.password_hash, body.password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "password is incorrect")
    secret = ctx.box.decrypt(user.totp_secret_enc or "", totp_context(user))
    step = verify_totp(secret, body.code, user.totp_last_step)
    if step is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid two-factor code")
    user.totp_enabled = False
    user.totp_secret_enc = None
    user.totp_last_step = step
    audit(db, request, "totp.disable", actor=user, target=user.username)
    db.commit()
    return user
