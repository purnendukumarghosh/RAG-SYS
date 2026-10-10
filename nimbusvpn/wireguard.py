"""WireGuard data-plane management.

The database is the source of truth. :class:`WireGuardManager` renders the desired
``wg-quick`` configuration from it and hands that to a backend, which converges the live
interface with ``wg syncconf``. Syncing only applies the difference, so established
tunnels are not interrupted.
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload, sessionmaker

from nimbusvpn.config import Settings
from nimbusvpn.crypto import KeyPair, SecretBox, generate_keypair, public_key_from_private
from nimbusvpn.db import Device, utcnow
from nimbusvpn.ipam import server_addresses

log = logging.getLogger(__name__)

SERVER_KEY_FILE = "server_key.enc"
SERVER_KEY_CONTEXT = "server-private-key"


class WireGuardError(RuntimeError):
    pass


@dataclass(frozen=True)
class PeerSpec:
    device_id: int
    name: str
    owner: str
    public_key: str
    preshared_key: str
    allowed_ips: list[str]


@dataclass(frozen=True)
class PeerStats:
    public_key: str
    endpoint: str | None
    latest_handshake: int
    rx_bytes: int
    tx_bytes: int


def psk_context(public_key: str) -> str:
    return f"psk:{public_key}"


def write_secret_file(path: Path, content: str) -> None:
    """Atomically write a file readable only by the current user (mode 0600)."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def load_or_create_server_keys(settings: Settings, box: SecretBox) -> KeyPair:
    """Load the server's WireGuard key pair; it is stored encrypted under the master secret."""
    path = settings.data_dir / SERVER_KEY_FILE
    if path.exists():
        private_key = box.decrypt(path.read_text(encoding="utf-8").strip(), SERVER_KEY_CONTEXT)
        return KeyPair(private_key, public_key_from_private(private_key))
    keys = generate_keypair()
    write_secret_file(path, box.encrypt(keys.private_key, SERVER_KEY_CONTEXT) + "\n")
    log.info("generated new server key pair, public key %s", keys.public_key)
    return keys


# --- Rendering ------------------------------------------------------------------------------


def _comment(text: str) -> str:
    # Names are validated at the API boundary; this is defence in depth against a newline
    # smuggling extra directives into the config file.
    return "".join(ch for ch in text if ch.isprintable())[:64]


def firewall_commands(settings: Settings, action: str) -> list[str]:
    """iptables commands that route, NAT and police VPN traffic.

    ``action`` is ``up`` (insert rules at the top of their chains, in order) or ``down``
    (delete the same rules).
    """
    iface, wan = settings.wg_interface, settings.wan_interface
    families: list[tuple[str, str, list[str]]] = [
        ("iptables", settings.wg_subnet_v4, [n for n in settings.blocked_networks if ":" not in n])
    ]
    if settings.ipv6_network is not None:
        families.append(
            ("ip6tables", settings.wg_subnet_v6, [n for n in settings.blocked_networks if ":" in n])
        )

    commands: list[str] = []
    for tool, subnet, blocked in families:
        forward: list[str] = [f"-i {iface} -d {net} -j DROP" for net in blocked]
        if settings.client_isolation:
            forward.append(f"-i {iface} -o {iface} -j DROP")
        forward += [
            f"-i {iface} -o {wan} -j ACCEPT",
            f"-i {wan} -o {iface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        ]
        nat = f"-s {subnet} -o {wan} -j MASQUERADE"
        if action == "up":
            commands += [f"{tool} -I FORWARD {i} {rule}" for i, rule in enumerate(forward, 1)]
            commands.append(f"{tool} -t nat -A POSTROUTING {nat}")
        else:
            commands += [f"{tool} -D FORWARD {rule}" for rule in forward]
            commands.append(f"{tool} -t nat -D POSTROUTING {nat}")
    return commands


def render_server_config(settings: Settings, private_key: str, peers: list[PeerSpec]) -> str:
    v4, v6 = server_addresses(settings.ipv4_network, settings.ipv6_network)
    addresses = [f"{v4}/{settings.ipv4_network.prefixlen}"]
    if v6 is not None:
        addresses.append(f"{v6}/{settings.ipv6_network.prefixlen}")

    lines = [
        "# Managed by NimbusVPN - manual edits are overwritten on the next sync.",
        "[Interface]",
        f"Address = {', '.join(addresses)}",
        f"ListenPort = {settings.wg_port}",
        f"PrivateKey = {private_key}",
    ]
    if settings.wg_mtu:
        lines.append(f"MTU = {settings.wg_mtu}")
    lines.append(f"PostUp = {'; '.join(firewall_commands(settings, 'up'))}")
    lines.append(f"PostDown = {'; '.join(firewall_commands(settings, 'down'))}")

    for peer in peers:
        lines += [
            "",
            f"# device {peer.device_id}: {_comment(peer.name)} (owner {_comment(peer.owner)})",
            "[Peer]",
            f"PublicKey = {peer.public_key}",
            f"PresharedKey = {peer.preshared_key}",
            f"AllowedIPs = {', '.join(peer.allowed_ips)}",
        ]
    return "\n".join(lines) + "\n"


def render_client_config(
    settings: Settings,
    *,
    private_key: str | None,
    ipv4: str,
    ipv6: str | None,
    server_public_key: str,
    preshared_key: str,
    device_name: str = "",
) -> str:
    addresses = [f"{ipv4}/32"] + ([f"{ipv6}/128"] if ipv6 else [])
    endpoint_host = settings.public_endpoint
    if ":" in endpoint_host and not endpoint_host.startswith("["):
        endpoint_host = f"[{endpoint_host}]"

    lines = []
    if device_name:
        lines.append(f"# NimbusVPN profile: {_comment(device_name)}")
    lines += [
        "[Interface]",
        f"PrivateKey = {private_key or '<paste the private key generated on this device>'}",
        f"Address = {', '.join(addresses)}",
    ]
    if settings.dns_servers:
        lines.append(f"DNS = {', '.join(settings.dns_servers)}")
    if settings.wg_mtu:
        lines.append(f"MTU = {settings.wg_mtu}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
        f"PresharedKey = {preshared_key}",
        f"Endpoint = {endpoint_host}:{settings.wg_port}",
        f"AllowedIPs = {', '.join(settings.allowed_ips)}",
    ]
    if settings.persistent_keepalive:
        lines.append(f"PersistentKeepalive = {settings.persistent_keepalive}")
    return "\n".join(lines) + "\n"


def parse_dump(text: str) -> dict[str, PeerStats]:
    """Parse ``wg show <iface> dump``.

    The first line describes the interface; each following line is a peer:
    public-key, preshared-key, endpoint, allowed-ips, latest-handshake, rx, tx, keepalive.
    """
    stats: dict[str, PeerStats] = {}
    for line in text.strip().splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            continue
        public_key, _psk, endpoint, _allowed, handshake, rx, tx, _keepalive = fields[:8]
        try:
            stats[public_key] = PeerStats(
                public_key=public_key,
                endpoint=None if endpoint == "(none)" else endpoint,
                latest_handshake=int(handshake),
                rx_bytes=int(rx),
                tx_bytes=int(tx),
            )
        except ValueError:
            log.warning("skipping unparsable wg dump line")
    return stats


# --- Backends -------------------------------------------------------------------------------


class WireGuardBackend(ABC):
    name: str

    def __init__(self, interface: str, runtime_dir: Path):
        self.interface = interface
        self.config_path = runtime_dir / f"{interface}.conf"

    @abstractmethod
    def apply(self, config: str) -> None: ...

    @abstractmethod
    def stats(self) -> dict[str, PeerStats]: ...

    @abstractmethod
    def is_up(self) -> bool: ...


class LinuxBackend(WireGuardBackend):
    """Drives the kernel WireGuard module with ``wg-quick`` and ``wg``."""

    name = "linux"

    def _run(self, *argv: str) -> str:
        try:
            result = subprocess.run(
                list(argv), check=True, capture_output=True, text=True, timeout=30
            )
        except FileNotFoundError as exc:
            raise WireGuardError(f"{argv[0]} not found - install wireguard-tools") from exc
        except subprocess.CalledProcessError as exc:
            raise WireGuardError(f"{' '.join(argv[:3])} failed: {exc.stderr.strip()}") from exc
        except subprocess.TimeoutExpired as exc:
            raise WireGuardError(f"{argv[0]} timed out") from exc
        return result.stdout

    def is_up(self) -> bool:
        try:
            self._run("wg", "show", self.interface, "public-key")
        except WireGuardError:
            return False
        return True

    def apply(self, config: str) -> None:
        write_secret_file(self.config_path, config)
        if not self.is_up():
            log.info("bringing up %s", self.interface)
            self._run("wg-quick", "up", str(self.config_path))
            return
        stripped = self._run("wg-quick", "strip", str(self.config_path))
        sync_path = self.config_path.with_suffix(".sync")
        write_secret_file(sync_path, stripped)
        try:
            self._run("wg", "syncconf", self.interface, str(sync_path))
        finally:
            sync_path.unlink(missing_ok=True)

    def stats(self) -> dict[str, PeerStats]:
        return parse_dump(self._run("wg", "show", self.interface, "dump"))


class DryRunBackend(WireGuardBackend):
    """Writes the config but touches no interface - for development, demos and tests."""

    name = "dryrun"

    def __init__(self, interface: str, runtime_dir: Path):
        super().__init__(interface, runtime_dir)
        self.applied: str | None = None
        self.apply_count = 0

    def apply(self, config: str) -> None:
        write_secret_file(self.config_path, config)
        self.applied = config
        self.apply_count += 1

    def stats(self) -> dict[str, PeerStats]:
        return {}

    def is_up(self) -> bool:
        return self.applied is not None


def make_backend(settings: Settings) -> WireGuardBackend:
    cls = LinuxBackend if settings.wg_backend == "linux" else DryRunBackend
    return cls(settings.wg_interface, settings.resolved_runtime_dir)


# --- Manager --------------------------------------------------------------------------------


@dataclass
class SyncStatus:
    last_sync_at: datetime | None = None
    last_error: str | None = None
    peer_count: int = 0
    sync_count: int = 0


class WireGuardManager:
    STATS_TTL_SECONDS = 2.0

    def __init__(
        self,
        settings: Settings,
        backend: WireGuardBackend,
        box: SecretBox,
        session_factory: sessionmaker[Session],
        server_keys: KeyPair,
    ):
        self.settings = settings
        self.backend = backend
        self.box = box
        self.session_factory = session_factory
        self.server_keys = server_keys
        self.status = SyncStatus()
        self._lock = threading.Lock()
        self._stats_cache: tuple[float, dict[str, PeerStats]] = (0.0, {})

    def active_peers(self, session: Session) -> list[PeerSpec]:
        now = utcnow()
        devices = session.scalars(
            select(Device).options(joinedload(Device.owner)).order_by(Device.id)
        ).all()
        peers = []
        for device in devices:
            if not device.is_active(now):
                continue
            allowed = [f"{device.ipv4}/32"] + ([f"{device.ipv6}/128"] if device.ipv6 else [])
            peers.append(
                PeerSpec(
                    device_id=device.id,
                    name=device.name,
                    owner=device.owner.username,
                    public_key=device.public_key,
                    preshared_key=self.box.decrypt(
                        device.preshared_key_enc, psk_context(device.public_key)
                    ),
                    allowed_ips=allowed,
                )
            )
        return peers

    def render(self) -> tuple[str, int]:
        with self.session_factory() as session:
            peers = self.active_peers(session)
        return render_server_config(self.settings, self.server_keys.private_key, peers), len(peers)

    def sync(self) -> bool:
        """Converge the live interface with the database. Never raises."""
        with self._lock:
            try:
                config, peer_count = self.render()
                self.backend.apply(config)
            except Exception as exc:
                self.status.last_error = str(exc)
                log.error("WireGuard sync failed: %s", exc)
                return False
            self.status.last_sync_at = utcnow()
            self.status.last_error = None
            self.status.peer_count = peer_count
            self.status.sync_count += 1
            self._stats_cache = (0.0, {})
            return True

    def stats(self) -> dict[str, PeerStats]:
        fetched_at, cached = self._stats_cache
        if time.monotonic() - fetched_at < self.STATS_TTL_SECONDS:
            return cached
        try:
            fresh = self.backend.stats()
        except WireGuardError as exc:
            log.warning("could not read WireGuard stats: %s", exc)
            fresh = {}
        self._stats_cache = (time.monotonic(), fresh)
        return fresh

    def is_online(self, stats: PeerStats | None) -> bool:
        if stats is None or stats.latest_handshake == 0:
            return False
        return time.time() - stats.latest_handshake < self.settings.handshake_online_seconds
