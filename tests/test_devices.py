from datetime import timedelta

from fastapi.testclient import TestClient

from nimbusvpn.crypto import generate_keypair, public_key_from_private
from nimbusvpn.db import Device, utcnow
from nimbusvpn.main import create_app

from .conftest import ADMIN_PASSWORD, login, make_settings


def wg_config(app) -> str:
    return app.state.ctx.wg.backend.applied


def parse_profile(config: str) -> dict[str, str]:
    values = {}
    for line in config.splitlines():
        if " = " in line:
            key, value = line.split(" = ", 1)
            values[key] = value
    return values


def test_create_device_returns_one_time_profile(client, app, user_headers):
    r = client.post("/api/devices", json={"name": "Pixel 9"}, headers=user_headers)
    assert r.status_code == 201, r.text
    body = r.json()
    device, profile = body["device"], parse_profile(body["config"])

    assert body["private_key_included"] is True
    assert body["qr_svg"].startswith("data:image/svg+xml")
    assert body["filename"] == "nimbus-Pixel-9.conf"
    assert device["ipv4"] == "10.8.0.2" and device["ipv6"] == "fd42:4e:42::2"
    assert device["status"] == "offline" and device["key_origin"] == "server"
    assert public_key_from_private(profile["PrivateKey"]) == device["public_key"]
    assert profile["PublicKey"] == app.state.ctx.wg.server_keys.public_key

    # The peer is live in WireGuard, with the same preshared key.
    config = wg_config(app)
    assert f"PublicKey = {device['public_key']}" in config
    assert f"PresharedKey = {profile['PresharedKey']}" in config

    # The private key is never stored: not in the database and not re-downloadable.
    with app.state.ctx.session_factory() as db:
        row = db.get(Device, device["id"])
        assert profile["PrivateKey"] not in repr(row.__dict__)
        assert profile["PresharedKey"] not in row.preshared_key_enc
    gone = client.get(f"/api/devices/{device['id']}/config", headers=user_headers)
    assert gone.status_code == 410


def test_bring_your_own_key(client, app, user_headers):
    keys = generate_keypair()
    r = client.post(
        "/api/devices", json={"name": "laptop", "public_key": keys.public_key}, headers=user_headers
    )
    assert r.status_code == 201
    body = r.json()
    assert body["private_key_included"] is False and body["qr_svg"] is None
    assert keys.private_key not in body["config"]
    assert body["device"]["key_origin"] == "client"
    again = client.get(f"/api/devices/{body['device']['id']}/config", headers=user_headers)
    assert again.status_code == 200
    duplicate = client.post(
        "/api/devices", json={"name": "dup", "public_key": keys.public_key}, headers=user_headers
    )
    assert duplicate.status_code == 409


def test_rejects_bad_input(client, user_headers):
    bad_key = client.post(
        "/api/devices", json={"name": "x", "public_key": "abc"}, headers=user_headers
    )
    assert bad_key.status_code == 422
    bad_name = client.post("/api/devices", json={"name": "a\nb"}, headers=user_headers)
    assert bad_name.status_code == 422


def test_users_are_isolated(client, admin_headers, user_headers):
    mine = client.post("/api/devices", json={"name": "alice-phone"}, headers=user_headers).json()
    theirs = client.post("/api/devices", json={"name": "admin-box"}, headers=admin_headers).json()
    own_list = client.get("/api/devices", headers=user_headers).json()
    assert [d["name"] for d in own_list] == ["alice-phone"]

    other_id = theirs["device"]["id"]
    for method, path in [
        ("get", f"/api/devices/{other_id}"),
        ("patch", f"/api/devices/{other_id}"),
        ("delete", f"/api/devices/{other_id}"),
        ("post", f"/api/devices/{other_id}/rotate"),
    ]:
        kwargs = {"json": {"enabled": False}} if method == "patch" else {}
        r = getattr(client, method)(path, headers=user_headers, **kwargs)
        assert r.status_code == 404, (method, path)

    assert client.get("/api/devices?scope=all", headers=user_headers).status_code == 403
    everything = client.get("/api/devices?scope=all", headers=admin_headers).json()
    assert {d["owner"] for d in everything} == {"alice", "admin"}
    # Admins may manage any device.
    assert (
        client.get(f"/api/devices/{mine['device']['id']}", headers=admin_headers).status_code == 200
    )


def test_disable_enable_and_delete_sync_wireguard(client, app, user_headers):
    device = client.post("/api/devices", json={"name": "tablet"}, headers=user_headers).json()[
        "device"
    ]
    key = device["public_key"]
    assert key in wg_config(app)

    r = client.patch(f"/api/devices/{device['id']}", json={"enabled": False}, headers=user_headers)
    assert r.json()["status"] == "disabled"
    assert key not in wg_config(app)

    client.patch(
        f"/api/devices/{device['id']}", json={"enabled": True, "name": "tab"}, headers=user_headers
    )
    assert key in wg_config(app)

    assert client.delete(f"/api/devices/{device['id']}", headers=user_headers).status_code == 204
    assert key not in wg_config(app)
    assert client.get(f"/api/devices/{device['id']}", headers=user_headers).status_code == 404


def test_rotate_replaces_keys(client, app, user_headers):
    created = client.post("/api/devices", json={"name": "phone"}, headers=user_headers).json()
    old_key = created["device"]["public_key"]
    rotated = client.post(
        f"/api/devices/{created['device']['id']}/rotate", headers=user_headers
    ).json()
    new_key = rotated["device"]["public_key"]
    assert new_key != old_key
    assert rotated["device"]["ipv4"] == created["device"]["ipv4"]
    assert old_key not in wg_config(app) and new_key in wg_config(app)
    assert (
        parse_profile(rotated["config"])["PresharedKey"]
        != parse_profile(created["config"])["PresharedKey"]
    )


def test_expired_devices_leave_the_tunnel(client, app, user_headers):
    device = client.post(
        "/api/devices", json={"name": "guest", "expires_in_days": 1}, headers=user_headers
    ).json()["device"]
    assert device["expires_at"] is not None and device["public_key"] in wg_config(app)

    with app.state.ctx.session_factory() as db:
        db.get(Device, device["id"]).expires_at = utcnow() - timedelta(minutes=1)
        db.commit()
    assert app.state.ctx.wg.sync()  # what the background reconcile loop does
    assert device["public_key"] not in wg_config(app)
    listed = client.get(f"/api/devices/{device['id']}", headers=user_headers).json()
    assert listed["status"] == "expired"

    # Extending access brings it back.
    client.patch(f"/api/devices/{device['id']}", json={"expires_in_days": 0}, headers=user_headers)
    assert device["public_key"] in wg_config(app)


def test_device_quota(tmp_path):
    app = create_app(make_settings(tmp_path, max_devices_per_user=2))
    with TestClient(app) as client:
        headers = login(client, "admin", ADMIN_PASSWORD)
        for i in range(2):
            assert (
                client.post("/api/devices", json={"name": f"d{i}"}, headers=headers).status_code
                == 201
            )
        r = client.post("/api/devices", json={"name": "one-too-many"}, headers=headers)
        assert r.status_code == 409 and "limit" in r.json()["detail"]


def test_address_reuse_after_delete(client, user_headers):
    a = client.post("/api/devices", json={"name": "a"}, headers=user_headers).json()["device"]
    b = client.post("/api/devices", json={"name": "b"}, headers=user_headers).json()["device"]
    assert (a["ipv4"], b["ipv4"]) == ("10.8.0.2", "10.8.0.3")
    client.delete(f"/api/devices/{a['id']}", headers=user_headers)
    c = client.post("/api/devices", json={"name": "c"}, headers=user_headers).json()["device"]
    assert c["ipv4"] == "10.8.0.2"


def test_state_survives_restart(tmp_path):
    settings = make_settings(tmp_path)
    with TestClient(create_app(settings)) as client:
        headers = login(client, "admin", ADMIN_PASSWORD)
        created = client.post("/api/devices", json={"name": "persist"}, headers=headers).json()
        server_key = created["config"].split("PublicKey = ")[1].split("\n")[0]
    restarted = create_app(settings)
    with TestClient(restarted) as client:
        assert restarted.state.ctx.wg.server_keys.public_key == server_key
        assert created["device"]["public_key"] in wg_config(restarted)
