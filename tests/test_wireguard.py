import ipaddress
import shutil
import subprocess

import pytest

from nimbusvpn.crypto import SecretBox, generate_keypair, generate_preshared_key
from nimbusvpn.ipam import AddressPoolExhausted, allocate, capacity
from nimbusvpn.wireguard import (
    PeerSpec,
    load_or_create_server_keys,
    parse_dump,
    render_client_config,
    render_server_config,
)

from .conftest import make_settings


def test_ipam_allocates_lowest_free_and_pairs_v6():
    v4 = ipaddress.IPv4Network("10.8.0.0/24")
    v6 = ipaddress.IPv6Network("fd00::/64")
    assert allocate(v4, v6, []) == ("10.8.0.2", "fd00::2")
    assert allocate(v4, v6, ["10.8.0.2", "10.8.0.4"]) == ("10.8.0.3", "fd00::3")
    assert allocate(v4, None, ["10.8.0.2"]) == ("10.8.0.3", None)


def test_ipam_exhaustion():
    v4 = ipaddress.IPv4Network("10.9.0.0/29")  # 8 addresses: network, server, 5 hosts, broadcast
    assert capacity(v4) == 5
    used = [f"10.9.0.{i}" for i in range(2, 7)]
    with pytest.raises(AddressPoolExhausted):
        allocate(v4, None, used)


def _peer(**kw):
    keys = generate_keypair()
    base = {
        "device_id": 1,
        "name": "phone",
        "owner": "alice",
        "public_key": keys.public_key,
        "preshared_key": generate_preshared_key(),
        "allowed_ips": ["10.8.0.2/32"],
    }
    base.update(kw)
    return PeerSpec(**base)


def test_server_config_contains_peers_and_firewall(tmp_path):
    settings = make_settings(tmp_path, wg_subnet_v6="")
    server = generate_keypair()
    peer = _peer()
    config = render_server_config(settings, server.private_key, [peer])
    assert "Address = 10.8.0.1/24\n" in config
    assert f"PrivateKey = {server.private_key}" in config
    assert f"PublicKey = {peer.public_key}" in config
    assert f"PresharedKey = {peer.preshared_key}" in config
    assert "AllowedIPs = 10.8.0.2/32" in config
    assert "-s 10.8.0.0/24 -o eth0 -j MASQUERADE" in config
    assert "-i wg0 -o wg0 -j DROP" in config  # client isolation
    assert "-d 169.254.0.0/16 -j DROP" in config  # cloud metadata service blocked
    assert "ip6tables" not in config


def test_server_config_isolation_off_and_ipv6(tmp_path):
    settings = make_settings(tmp_path, client_isolation=False)
    config = render_server_config(settings, generate_keypair().private_key, [])
    assert "-i wg0 -o wg0 -j DROP" not in config
    assert "Address = 10.8.0.1/24, fd42:4e:42::1/64" in config
    assert "ip6tables -t nat -A POSTROUTING -s fd42:4e:42::/64" in config


def test_comment_injection_is_neutralised(tmp_path):
    settings = make_settings(tmp_path)
    peer = _peer(name="evil\n[Peer]\nPublicKey = x")
    config = render_server_config(settings, generate_keypair().private_key, [peer])
    lines = config.splitlines()
    assert lines.count("[Peer]") == 1
    assert sum(line.startswith("PublicKey") for line in lines) == 1


def test_client_config(tmp_path):
    settings = make_settings(tmp_path, client_dns="9.9.9.9", wg_mtu=1380)
    keys, server, psk = generate_keypair(), generate_keypair(), generate_preshared_key()
    config = render_client_config(
        settings,
        private_key=keys.private_key,
        ipv4="10.8.0.5",
        ipv6="fd42:4e:42::5",
        server_public_key=server.public_key,
        preshared_key=psk,
    )
    assert f"PrivateKey = {keys.private_key}" in config
    assert "Address = 10.8.0.5/32, fd42:4e:42::5/128" in config
    assert "DNS = 9.9.9.9" in config
    assert "MTU = 1380" in config
    assert "Endpoint = vpn.example.test:51820" in config
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in config
    assert "PersistentKeepalive = 25" in config


def test_client_config_ipv6_endpoint_is_bracketed(tmp_path):
    settings = make_settings(tmp_path, public_endpoint="2001:db8::10")
    config = render_client_config(
        settings,
        private_key=None,
        ipv4="10.8.0.5",
        ipv6=None,
        server_public_key=generate_keypair().public_key,
        preshared_key=generate_preshared_key(),
    )
    assert "Endpoint = [2001:db8::10]:51820" in config
    assert "PrivateKey = <paste" in config


@pytest.mark.skipif(shutil.which("wg-quick") is None, reason="wireguard-tools not installed")
def test_server_config_is_accepted_by_wg_quick(tmp_path):
    settings = make_settings(tmp_path)
    path = tmp_path / "wg0.conf"
    path.write_text(render_server_config(settings, generate_keypair().private_key, [_peer()]))
    out = subprocess.run(["wg-quick", "strip", str(path)], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "PostUp" not in out.stdout and "[Peer]" in out.stdout


def test_parse_dump():
    dump = (
        "privkey\tpubkey\t51820\toff\n"
        "peerA\tpskA\t203.0.113.7:4500\t10.8.0.2/32\t1700000000\t1024\t2048\t25\n"
        "peerB\t(none)\t(none)\t10.8.0.3/32\t0\t0\t0\toff\n"
        "garbage line\n"
    )
    stats = parse_dump(dump)
    assert set(stats) == {"peerA", "peerB"}
    assert stats["peerA"].endpoint == "203.0.113.7:4500"
    assert stats["peerA"].latest_handshake == 1700000000
    assert (stats["peerA"].rx_bytes, stats["peerA"].tx_bytes) == (1024, 2048)
    assert stats["peerB"].endpoint is None and stats["peerB"].latest_handshake == 0


def test_server_key_persisted_encrypted(tmp_path):
    settings = make_settings(tmp_path)
    settings.data_dir.mkdir(parents=True)
    box = SecretBox(settings.secret_key)
    first = load_or_create_server_keys(settings, box)
    stored = (settings.data_dir / "server_key.enc").read_text()
    assert first.private_key not in stored
    assert (settings.data_dir / "server_key.enc").stat().st_mode & 0o777 == 0o600
    assert load_or_create_server_keys(settings, box) == first
