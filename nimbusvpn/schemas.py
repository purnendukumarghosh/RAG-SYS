"""Request and response models for the HTTP API."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator

from nimbusvpn.crypto import is_valid_key
from nimbusvpn.security import USERNAME_RE


def _as_utc(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


UTCDateTime = Annotated[datetime, AfterValidator(_as_utc)]

# Printable, no newlines: device names end up as comments in wg0.conf.
DeviceName = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9 _.()'@+-]+$")]
Username = Annotated[str, Field(min_length=3, max_length=32, pattern=USERNAME_RE.pattern)]
Role = Literal["admin", "user"]


class LoginRequest(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)
    totp_code: str | None = Field(default=None, max_length=10)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: Role
    enabled: bool
    totp_enabled: bool
    max_devices: int | None
    created_at: UTCDateTime
    last_login_at: UTCDateTime | None
    locked_until: UTCDateTime | None


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105
    expires_in: int
    user: UserOut


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class TotpSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str
    qr_svg: str


class TotpCode(BaseModel):
    code: str = Field(max_length=10)


class TotpDisable(BaseModel):
    password: str = Field(max_length=256)
    code: str = Field(max_length=10)


class DeviceCreate(BaseModel):
    name: DeviceName
    public_key: str | None = Field(
        default=None, description="Bring your own key: the private key never leaves the device."
    )
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)

    @field_validator("public_key")
    @classmethod
    def _valid_key(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        value = value.strip()
        if not is_valid_key(value):
            raise ValueError("public_key must be a base64-encoded 32-byte WireGuard key")
        return value


class DeviceUpdate(BaseModel):
    name: DeviceName | None = None
    enabled: bool | None = None
    expires_in_days: int | None = Field(default=None, ge=0, le=3650, description="0 = never")


class DeviceOut(BaseModel):
    id: int
    name: str
    owner: str
    ipv4: str
    ipv6: str | None
    public_key: str
    key_origin: Literal["server", "client"]
    enabled: bool
    status: Literal["online", "offline", "disabled", "expired"]
    created_at: UTCDateTime
    expires_at: UTCDateTime | None
    rotated_at: UTCDateTime | None
    last_handshake_at: UTCDateTime | None
    endpoint: str | None
    rx_bytes: int
    tx_bytes: int


class DeviceProfile(BaseModel):
    """A client profile. With server-generated keys it is only ever returned once."""

    device: DeviceOut
    config: str
    filename: str
    qr_svg: str | None
    private_key_included: bool


class UserCreate(BaseModel):
    username: Username
    password: str = Field(max_length=256)
    role: Role = "user"
    max_devices: int | None = Field(default=None, ge=1, le=1000)


class UserUpdate(BaseModel):
    role: Role | None = None
    enabled: bool | None = None
    password: str | None = Field(default=None, max_length=256)
    max_devices: int | None = Field(default=None, ge=0, le=1000, description="0 = default")
    unlock: bool = False
    reset_totp: bool = False


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: UTCDateTime
    actor: str | None
    action: str
    target: str | None
    ip: str | None
    details: str | None


class ServerInfo(BaseModel):
    version: str
    backend: str
    interface: str
    interface_up: bool
    public_key: str
    endpoint: str
    listen_port: int
    subnet_v4: str
    subnet_v6: str | None
    dns: list[str]
    client_isolation: bool
    active_peers: int
    online_peers: int
    total_devices: int
    total_users: int
    address_capacity: int
    last_sync_at: UTCDateTime | None
    last_sync_error: str | None
