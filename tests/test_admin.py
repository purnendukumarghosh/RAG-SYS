from .conftest import USER_PASSWORD, login


def _user_id(client, headers, username):
    return next(
        u["id"]
        for u in client.get("/api/admin/users", headers=headers).json()
        if u["username"] == username
    )


def test_admin_endpoints_require_admin(client, user_headers):
    for path in ["/api/admin/users", "/api/admin/server", "/api/admin/audit"]:
        assert client.get(path, headers=user_headers).status_code == 403


def test_create_user_validation(client, admin_headers):
    weak = client.post(
        "/api/admin/users", json={"username": "bob", "password": "short"}, headers=admin_headers
    )
    assert weak.status_code == 422
    contains_name = client.post(
        "/api/admin/users",
        json={"username": "bobby", "password": "bobby-is-my-password"},
        headers=admin_headers,
    )
    assert contains_name.status_code == 422
    bad_name = client.post(
        "/api/admin/users",
        json={"username": "no spaces", "password": USER_PASSWORD},
        headers=admin_headers,
    )
    assert bad_name.status_code == 422
    ok = client.post(
        "/api/admin/users",
        json={"username": "Bob", "password": USER_PASSWORD},
        headers=admin_headers,
    )
    assert ok.status_code == 201 and ok.json()["username"] == "bob"
    dup = client.post(
        "/api/admin/users",
        json={"username": "BOB", "password": USER_PASSWORD},
        headers=admin_headers,
    )
    assert dup.status_code == 409


def test_cannot_remove_last_admin(client, admin_headers):
    admin_id = _user_id(client, admin_headers, "admin")
    demote = client.patch(
        f"/api/admin/users/{admin_id}", json={"role": "user"}, headers=admin_headers
    )
    assert demote.status_code == 409
    disable = client.patch(
        f"/api/admin/users/{admin_id}", json={"enabled": False}, headers=admin_headers
    )
    assert disable.status_code == 409
    delete = client.delete(f"/api/admin/users/{admin_id}", headers=admin_headers)
    assert delete.status_code == 409


def test_disabling_user_removes_their_peers(client, app, admin_headers, user_headers):
    key = client.post("/api/devices", json={"name": "p"}, headers=user_headers).json()["device"][
        "public_key"
    ]
    alice = _user_id(client, admin_headers, "alice")
    client.patch(f"/api/admin/users/{alice}", json={"enabled": False}, headers=admin_headers)
    assert key not in app.state.ctx.wg.backend.applied
    client.patch(f"/api/admin/users/{alice}", json={"enabled": True}, headers=admin_headers)
    assert key in app.state.ctx.wg.backend.applied


def test_delete_user_cascades_devices(client, app, admin_headers, user_headers):
    key = client.post("/api/devices", json={"name": "p"}, headers=user_headers).json()["device"][
        "public_key"
    ]
    alice = _user_id(client, admin_headers, "alice")
    assert client.delete(f"/api/admin/users/{alice}", headers=admin_headers).status_code == 204
    assert key not in app.state.ctx.wg.backend.applied
    assert client.get("/api/devices?scope=all", headers=admin_headers).json() == []


def test_password_reset_and_unlock(client, admin_headers, user_headers, settings):
    alice = _user_id(client, admin_headers, "alice")
    for _ in range(settings.login_max_attempts):
        client.post("/api/auth/login", json={"username": "alice", "password": "bad"})
    assert (
        client.post(
            "/api/auth/login", json={"username": "alice", "password": USER_PASSWORD}
        ).status_code
        == 429
    )

    client.patch(
        f"/api/admin/users/{alice}",
        json={"unlock": True, "password": "reset-by-the-admin"},
        headers=admin_headers,
    )
    assert client.get("/api/auth/me", headers=user_headers).status_code == 401  # sessions revoked
    login(client, "alice", "reset-by-the-admin")


def test_server_info_and_audit(client, admin_headers, user_headers):
    client.post("/api/devices", json={"name": "phone"}, headers=user_headers)
    info = client.get("/api/admin/server", headers=admin_headers).json()
    assert info["backend"] == "dryrun" and info["interface_up"] is True
    assert info["active_peers"] == 1 and info["total_users"] == 2
    assert info["endpoint"] == "vpn.example.test:51820"
    assert info["last_sync_error"] is None

    synced = client.post("/api/admin/sync", headers=admin_headers)
    assert synced.status_code == 200

    events = client.get("/api/admin/audit", headers=admin_headers).json()
    actions = [e["action"] for e in events]
    assert {"login.success", "user.create", "device.create", "server.sync"} <= set(actions)
    filtered = client.get("/api/admin/audit?action=device", headers=admin_headers).json()
    assert filtered and all(e["action"].startswith("device") for e in filtered)
