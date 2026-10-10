"""Device (WireGuard peer) endpoints."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from nimbusvpn.crypto import generate_keypair, generate_preshared_key, is_valid_key
from nimbusvpn.db import Device, User, utcnow
from nimbusvpn.deps import AppContext, audit, current_user, get_ctx, get_db, qr_svg_data_uri
from nimbusvpn.ipam import AddressPoolExhausted, allocate
from nimbusvpn.schemas import DeviceCreate, DeviceOut, DeviceProfile, DeviceUpdate
from nimbusvpn.wireguard import PeerStats, psk_context, render_client_config

router = APIRouter(prefix="/api/devices", tags=["devices"])


class RotateRequest(BaseModel):
    public_key: str | None = None

    @field_validator("public_key")
    @classmethod
    def _valid_key(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        if not is_valid_key(value.strip()):
            raise ValueError("public_key must be a base64-encoded 32-byte WireGuard key")
        return value.strip()


def device_status(
    ctx: AppContext, device: Device, stats: PeerStats | None, now: datetime
) -> Literal["online", "offline", "disabled", "expired"]:
    if device.is_expired(now):
        return "expired"
    if not device.enabled or not device.owner.enabled:
        return "disabled"
    return "online" if ctx.wg.is_online(stats) else "offline"


def to_out(ctx: AppContext, device: Device, stats: dict[str, PeerStats]) -> DeviceOut:
    peer = stats.get(device.public_key)
    handshake = (
        datetime.fromtimestamp(peer.latest_handshake, UTC)
        if peer and peer.latest_handshake
        else None
    )
    return DeviceOut(
        id=device.id,
        name=device.name,
        owner=device.owner.username,
        ipv4=device.ipv4,
        ipv6=device.ipv6,
        public_key=device.public_key,
        key_origin=device.key_origin,
        enabled=device.enabled,
        status=device_status(ctx, device, peer, utcnow()),
        created_at=device.created_at,
        expires_at=device.expires_at,
        rotated_at=device.rotated_at,
        last_handshake_at=handshake,
        endpoint=peer.endpoint if peer else None,
        rx_bytes=peer.rx_bytes if peer else 0,
        tx_bytes=peer.tx_bytes if peer else 0,
    )


def profile(
    ctx: AppContext, device: Device, private_key: str | None, preshared_key: str
) -> DeviceProfile:
    config = render_client_config(
        ctx.settings,
        private_key=private_key,
        ipv4=device.ipv4,
        ipv6=device.ipv6,
        server_public_key=ctx.wg.server_keys.public_key,
        preshared_key=preshared_key,
        device_name=device.name,
    )
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", device.name).strip("-")[:32] or f"device-{device.id}"
    return DeviceProfile(
        device=to_out(ctx, device, ctx.wg.stats()),
        config=config,
        filename=f"nimbus-{slug}.conf",
        qr_svg=qr_svg_data_uri(config) if private_key else None,
        private_key_included=private_key is not None,
    )


def get_owned_device(db: Session, user: User, device_id: int) -> Device:
    device = db.get(Device, device_id, options=[joinedload(Device.owner)])
    # 404 rather than 403, so other users' device IDs are not confirmed to exist.
    if device is None or (device.user_id != user.id and not user.is_admin):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "device not found")
    return device


def ensure_key_unused(ctx: AppContext, db: Session, public_key: str) -> None:
    if public_key == ctx.wg.server_keys.public_key or db.scalar(
        select(Device.id).where(Device.public_key == public_key)
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, "this public key is already registered")


@router.get("", response_model=list[DeviceOut])
def list_devices(
    scope: Literal["mine", "all"] = Query("mine"),
    user: User = Depends(current_user),
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> list[DeviceOut]:
    query = select(Device).options(joinedload(Device.owner)).order_by(Device.id)
    if scope == "all":
        if not user.is_admin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    else:
        query = query.where(Device.user_id == user.id)
    stats = ctx.wg.stats()
    return [to_out(ctx, device, stats) for device in db.scalars(query).all()]


@router.post("", response_model=DeviceProfile, status_code=status.HTTP_201_CREATED)
def create_device(
    body: DeviceCreate,
    request: Request,
    user: User = Depends(current_user),
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> DeviceProfile:
    limit = user.max_devices or ctx.settings.max_devices_per_user
    owned = db.scalar(select(func.count()).select_from(Device).where(Device.user_id == user.id))
    if owned >= limit:
        raise HTTPException(status.HTTP_409_CONFLICT, f"device limit reached ({limit})")

    if body.public_key:
        ensure_key_unused(ctx, db, body.public_key)
        public_key, private_key, origin = body.public_key, None, "client"
    else:
        keys = generate_keypair()
        public_key, private_key, origin = keys.public_key, keys.private_key, "server"
    preshared_key = generate_preshared_key()
    expires_at = utcnow() + timedelta(days=body.expires_in_days) if body.expires_in_days else None

    device = None
    for _attempt in range(5):  # another request may grab the same address concurrently
        used = db.scalars(select(Device.ipv4)).all()
        try:
            ipv4, ipv6 = allocate(ctx.settings.ipv4_network, ctx.settings.ipv6_network, used)
        except AddressPoolExhausted as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
        device = Device(
            owner=user,
            name=body.name,
            public_key=public_key,
            preshared_key_enc=ctx.box.encrypt(preshared_key, psk_context(public_key)),
            ipv4=ipv4,
            ipv6=ipv6,
            key_origin=origin,
            expires_at=expires_at,
        )
        db.add(device)
        try:
            db.flush()
            break
        except IntegrityError:
            db.rollback()
            ensure_key_unused(ctx, db, public_key)
            device = None
    if device is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "could not allocate an address")

    audit(
        db,
        request,
        "device.create",
        actor=user,
        target=f"device:{device.id}",
        name=device.name,
        ipv4=device.ipv4,
        key_origin=origin,
    )
    db.commit()
    ctx.wg.sync()
    return profile(ctx, device, private_key, preshared_key)


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(
    device_id: int,
    user: User = Depends(current_user),
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> DeviceOut:
    return to_out(ctx, get_owned_device(db, user, device_id), ctx.wg.stats())


@router.patch("/{device_id}", response_model=DeviceOut)
def update_device(
    device_id: int,
    body: DeviceUpdate,
    request: Request,
    user: User = Depends(current_user),
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> DeviceOut:
    device = get_owned_device(db, user, device_id)
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    if "name" in changes:
        device.name = body.name
    if "enabled" in changes:
        device.enabled = body.enabled
    if "expires_in_days" in changes:
        days = body.expires_in_days
        device.expires_at = utcnow() + timedelta(days=days) if days else None
    audit(db, request, "device.update", actor=user, target=f"device:{device.id}", **changes)
    db.commit()
    if changes.keys() & {"enabled", "expires_in_days"}:
        ctx.wg.sync()
    return to_out(ctx, device, ctx.wg.stats())


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_device(
    device_id: int,
    request: Request,
    user: User = Depends(current_user),
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> None:
    device = get_owned_device(db, user, device_id)
    audit(
        db,
        request,
        "device.delete",
        actor=user,
        target=f"device:{device.id}",
        name=device.name,
        owner=device.owner.username,
    )
    db.delete(device)
    db.commit()
    ctx.wg.sync()


@router.post("/{device_id}/rotate", response_model=DeviceProfile)
def rotate_device_keys(
    device_id: int,
    request: Request,
    body: RotateRequest | None = None,
    user: User = Depends(current_user),
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> DeviceProfile:
    """Replace the device's key pair and preshared key; the old keys stop working at once."""
    device = get_owned_device(db, user, device_id)
    if body and body.public_key:
        ensure_key_unused(ctx, db, body.public_key)
        public_key, private_key, origin = body.public_key, None, "client"
    else:
        keys = generate_keypair()
        public_key, private_key, origin = keys.public_key, keys.private_key, "server"
    preshared_key = generate_preshared_key()
    device.public_key = public_key
    device.preshared_key_enc = ctx.box.encrypt(preshared_key, psk_context(public_key))
    device.key_origin = origin
    device.rotated_at = utcnow()
    audit(db, request, "device.rotate", actor=user, target=f"device:{device.id}", key_origin=origin)
    db.commit()
    ctx.wg.sync()
    return profile(ctx, device, private_key, preshared_key)


@router.get("/{device_id}/config", response_model=DeviceProfile)
def device_config(
    device_id: int,
    user: User = Depends(current_user),
    ctx: AppContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> DeviceProfile:
    """Re-download a profile. Only possible for bring-your-own-key devices."""
    device = get_owned_device(db, user, device_id)
    if device.key_origin == "server":
        raise HTTPException(
            status.HTTP_410_GONE,
            "the private key for this device was shown once and is not stored - "
            "rotate the keys to get a new profile",
        )
    preshared_key = ctx.box.decrypt(device.preshared_key_enc, psk_context(device.public_key))
    return profile(ctx, device, None, preshared_key)
