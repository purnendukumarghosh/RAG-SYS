"""Administration endpoints: users, server status, audit log."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nimbusvpn import __version__
from nimbusvpn.db import AuditEvent, Device, User
from nimbusvpn.deps import AppContext, admin_user, audit, get_ctx, get_db
from nimbusvpn.ipam import capacity
from nimbusvpn.schemas import AuditOut, ServerInfo, UserCreate, UserOut, UserUpdate
from nimbusvpn.security import hash_password, password_problems

router = APIRouter(prefix="/api/admin", tags=["admin"])


class AdminUserOut(UserOut):
    device_count: int = 0


def _check_password(ctx: AppContext, password: str, username: str) -> None:
    problems = password_problems(password, username, ctx.settings.min_password_length)
    if problems:
        raise HTTPException(422, "password " + "; ".join(problems))


def _other_enabled_admins(db: Session, user: User) -> int:
    return db.scalar(
        select(func.count())
        .select_from(User)
        .where(User.role == "admin", User.enabled.is_(True), User.id != user.id)
    )


def _with_count(db: Session, user: User) -> AdminUserOut:
    count = db.scalar(select(func.count()).select_from(Device).where(Device.user_id == user.id))
    return AdminUserOut.model_validate(user).model_copy(update={"device_count": count})


@router.get("/users", response_model=list[AdminUserOut])
def list_users(_: User = Depends(admin_user), db: Session = Depends(get_db)):
    return [_with_count(db, u) for u in db.scalars(select(User).order_by(User.id)).all()]


@router.post("/users", response_model=AdminUserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreate,
    request: Request,
    admin: User = Depends(admin_user),
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
):
    username = body.username.lower()
    if db.scalar(select(User.id).where(User.username == username)):
        raise HTTPException(status.HTTP_409_CONFLICT, "username already exists")
    _check_password(ctx, body.password, username)
    user = User(
        username=username,
        password_hash=hash_password(body.password),
        role=body.role,
        max_devices=body.max_devices,
    )
    db.add(user)
    db.flush()
    audit(db, request, "user.create", actor=admin, target=f"user:{username}", role=body.role)
    db.commit()
    return _with_count(db, user)


@router.patch("/users/{user_id}", response_model=AdminUserOut)
def update_user(
    user_id: int,
    body: UserUpdate,
    request: Request,
    admin: User = Depends(admin_user),
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")

    losing_admin = (body.role is not None and body.role != "admin") or body.enabled is False
    if user.is_admin and losing_admin and _other_enabled_admins(db, user) == 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "cannot remove the last active admin")

    changed: list[str] = []
    revoke_sessions = False
    if body.role is not None and body.role != user.role:
        user.role = body.role
        changed.append("role")
        revoke_sessions = True
    if body.enabled is not None and body.enabled != user.enabled:
        user.enabled = body.enabled
        changed.append("enabled")
        revoke_sessions = revoke_sessions or not body.enabled
    if body.password:
        _check_password(ctx, body.password, user.username)
        user.password_hash = hash_password(body.password)
        changed.append("password")
        revoke_sessions = True
    if body.max_devices is not None:
        user.max_devices = body.max_devices or None
        changed.append("max_devices")
    if body.unlock:
        user.locked_until = None
        user.failed_logins = 0
        changed.append("unlock")
    if body.reset_totp:
        user.totp_enabled = False
        user.totp_secret_enc = None
        changed.append("reset_totp")
    if revoke_sessions:
        user.token_version += 1

    audit(db, request, "user.update", actor=admin, target=f"user:{user.username}", fields=changed)
    db.commit()
    if "enabled" in changed:
        ctx.wg.sync()  # a disabled user's devices leave the tunnel immediately
    return _with_count(db, user)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    request: Request,
    admin: User = Depends(admin_user),
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> None:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if user.id == admin.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "you cannot delete your own account")
    if user.is_admin and _other_enabled_admins(db, user) == 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "cannot remove the last active admin")
    audit(db, request, "user.delete", actor=admin, target=f"user:{user.username}")
    db.delete(user)
    db.commit()
    ctx.wg.sync()


@router.get("/server", response_model=ServerInfo)
def server_info(
    _: User = Depends(admin_user),
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> ServerInfo:
    settings, wg = ctx.settings, ctx.wg
    stats = wg.stats()
    return ServerInfo(
        version=__version__,
        backend=wg.backend.name,
        interface=settings.wg_interface,
        interface_up=wg.backend.is_up(),
        public_key=wg.server_keys.public_key,
        endpoint=f"{settings.public_endpoint}:{settings.wg_port}",
        listen_port=settings.wg_port,
        subnet_v4=settings.wg_subnet_v4,
        subnet_v6=settings.wg_subnet_v6 or None,
        dns=settings.dns_servers,
        client_isolation=settings.client_isolation,
        active_peers=wg.status.peer_count,
        online_peers=sum(1 for peer in stats.values() if wg.is_online(peer)),
        total_devices=db.scalar(select(func.count()).select_from(Device)),
        total_users=db.scalar(select(func.count()).select_from(User)),
        address_capacity=capacity(settings.ipv4_network),
        last_sync_at=wg.status.last_sync_at,
        last_sync_error=wg.status.last_error,
    )


@router.post("/sync", response_model=ServerInfo)
def force_sync(
    request: Request,
    admin: User = Depends(admin_user),
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> ServerInfo:
    ok = ctx.wg.sync()
    audit(db, request, "server.sync", actor=admin, ok=ok)
    db.commit()
    return server_info(admin, ctx, db)


@router.get("/audit", response_model=list[AuditOut])
def audit_log(
    limit: int = Query(100, ge=1, le=1000),
    action: str | None = Query(None, max_length=48),
    _: User = Depends(admin_user),
    db: Session = Depends(get_db),
):
    query = select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)
    if action:
        query = query.where(AuditEvent.action.startswith(action, autoescape=True))
    return db.scalars(query).all()
