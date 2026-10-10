"""Runtime configuration, loaded from environment variables prefixed with ``NIMBUS_``."""

from __future__ import annotations

import ipaddress
from functools import cached_property
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

KEYGEN_HINT = 'generate one with: python -c "import secrets; print(secrets.token_urlsafe(48))"'


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NIMBUS_", env_file=".env", extra="ignore")

    # --- Core -----------------------------------------------------------------------------
    secret_key: str = Field(
        default="",
        description="Master secret. Derives the JWT signing key and the at-rest encryption key.",
    )
    data_dir: Path = Path("./data")
    runtime_dir: Path | None = Field(
        default=None,
        description="Where the rendered wg0.conf (with plaintext keys) lives; use a tmpfs.",
    )
    database_url: str | None = None
    enable_api_docs: bool = False

    # --- Bootstrap admin (only used when the database has no users) -------------------------
    admin_username: str | None = None
    admin_password: str | None = None

    # --- Authentication -------------------------------------------------------------------
    access_token_ttl_minutes: int = Field(default=60, ge=5, le=24 * 60)
    login_max_attempts: int = Field(default=5, ge=1)
    login_lockout_minutes: int = Field(default=15, ge=1)
    login_ip_limit_per_window: int = Field(default=20, ge=1)
    login_ip_window_seconds: int = Field(default=300, ge=1)
    min_password_length: int = Field(default=12, ge=8)

    # --- WireGuard ------------------------------------------------------------------------
    wg_backend: Literal["linux", "dryrun"] = "linux"
    wg_interface: str = Field(default="wg0", pattern=r"^[a-zA-Z0-9_=+.-]{1,15}$")
    wg_port: int = Field(default=51820, ge=1, le=65535)
    wg_subnet_v4: str = "10.8.0.0/24"
    wg_subnet_v6: str = "fd42:4e:42::/64"
    wg_mtu: int | None = Field(default=None, ge=1280, le=9000)
    wan_interface: str = Field(default="eth0", pattern=r"^[a-zA-Z0-9_.:-]{1,15}$")
    client_isolation: bool = True
    blocked_destinations: str = "169.254.0.0/16"

    # --- Client profile -------------------------------------------------------------------
    public_endpoint: str = Field(default="vpn.example.com", pattern=r"^[A-Za-z0-9.:\[\]-]{1,253}$")
    client_dns: str = "1.1.1.1, 1.0.0.1"
    client_allowed_ips: str = "0.0.0.0/0, ::/0"
    persistent_keepalive: int = Field(default=25, ge=0, le=65535)

    # --- Policy ---------------------------------------------------------------------------
    max_devices_per_user: int = Field(default=5, ge=1)
    handshake_online_seconds: int = Field(default=180, ge=30)
    reconcile_interval_seconds: int = Field(
        default=30, ge=0, description="0 disables the background reconcile loop (tests)."
    )

    @field_validator("wg_subnet_v4")
    @classmethod
    def _check_v4(cls, value: str) -> str:
        net = ipaddress.ip_network(value, strict=True)
        if net.version != 4 or net.prefixlen > 29:
            raise ValueError("wg_subnet_v4 must be an IPv4 network of /29 or larger")
        return str(net)

    @field_validator("wg_subnet_v6")
    @classmethod
    def _check_v6(cls, value: str) -> str:
        if not value.strip():
            return ""
        net = ipaddress.ip_network(value, strict=True)
        if net.version != 6:
            raise ValueError("wg_subnet_v6 must be an IPv6 network (or empty to disable)")
        return str(net)

    @field_validator("client_dns", "client_allowed_ips", "blocked_destinations")
    @classmethod
    def _check_csv_addresses(cls, value: str, info) -> str:
        for item in _split_csv(value):
            if info.field_name == "client_dns":
                ipaddress.ip_address(item)
            else:
                ipaddress.ip_network(item, strict=False)
        return value

    @model_validator(mode="after")
    def _check_secret_and_subnets(self) -> Settings:
        if len(self.secret_key) < 32:
            raise ValueError(f"NIMBUS_SECRET_KEY must be at least 32 characters; {KEYGEN_HINT}")
        if self.ipv6_network is not None:
            v4_hosts = self.ipv4_network.num_addresses
            if self.ipv6_network.num_addresses < v4_hosts:
                raise ValueError("wg_subnet_v6 must be at least as large as wg_subnet_v4")
        return self

    # --- Derived values -------------------------------------------------------------------
    @cached_property
    def ipv4_network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(self.wg_subnet_v4)

    @cached_property
    def ipv6_network(self) -> ipaddress.IPv6Network | None:
        return ipaddress.IPv6Network(self.wg_subnet_v6) if self.wg_subnet_v6 else None

    @property
    def resolved_database_url(self) -> str:
        return self.database_url or f"sqlite:///{(self.data_dir / 'nimbus.db').as_posix()}"

    @property
    def resolved_runtime_dir(self) -> Path:
        return self.runtime_dir or self.data_dir / "run"

    @property
    def dns_servers(self) -> list[str]:
        return _split_csv(self.client_dns)

    @property
    def allowed_ips(self) -> list[str]:
        return _split_csv(self.client_allowed_ips)

    @property
    def blocked_networks(self) -> list[str]:
        return _split_csv(self.blocked_destinations)
