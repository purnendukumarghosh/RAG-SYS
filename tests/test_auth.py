import time

import pyotp
from fastapi.testclient import TestClient

from nimbusvpn.main import create_app
from nimbusvpn.security import TokenService, verify_totp

from .conftest import ADMIN_PASSWORD, USER_PASSWORD, login, make_settings


def test_health_and_security_headers(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"


def test_dashboard_served(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "NimbusVPN" in response.text
    assert client.get("/static/app.js").status_code == 200


def test_api_docs_disabled_by_default(client):
    assert client.get("/api/docs").status_code == 404
    assert client.get("/api/openapi.json").status_code == 404


def test_login_success_and_me(client):
    headers = login(client, "ADMIN", ADMIN_PASSWORD)  # usernames are case-insensitive
    me = client.get("/api/auth/me", headers=headers).json()
    assert me["username"] == "admin" and me["role"] == "admin"
    assert me["last_login_at"].endswith("Z") or me["last_login_at"].endswith("+00:00")


def test_requires_authentication(client):
    assert client.get("/api/devices").status_code == 401
    assert client.get("/api/devices", headers={"Authorization": "Bearer junk"}).status_code == 401


def test_wrong_password_and_unknown_user_look_the_same(client):
    bad = client.post("/api/auth/login", json={"username": "admin", "password": "nope"})
    unknown = client.post("/api/auth/login", json={"username": "ghost", "password": "nope"})
    assert bad.status_code == unknown.status_code == 401
    assert bad.json() == unknown.json()


def test_account_lockout(client, settings):
    for _ in range(settings.login_max_attempts):
        r = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
        assert r.status_code == 401
    locked = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    assert locked.status_code == 429


def test_unknown_user_lockout_mirrors_real_accounts(client, settings):
    for _ in range(settings.login_max_attempts):
        assert (
            client.post("/api/auth/login", json={"username": "ghost", "password": "x"}).status_code
            == 401
        )
    assert (
        client.post("/api/auth/login", json={"username": "ghost", "password": "x"}).status_code
        == 429
    )


def test_ip_rate_limit(tmp_path):
    app = create_app(make_settings(tmp_path, login_ip_limit_per_window=3))
    with TestClient(app) as client:
        codes = [
            client.post("/api/auth/login", json={"username": "x", "password": "y"}).status_code
            for _ in range(4)
        ]
    assert codes == [401, 401, 401, 429]


def test_logout_revokes_token(client, admin_headers):
    assert client.post("/api/auth/logout", headers=admin_headers).status_code == 204
    assert client.get("/api/auth/me", headers=admin_headers).status_code == 401


def test_change_password(client, admin_headers):
    weak = client.post(
        "/api/auth/password",
        json={"current_password": ADMIN_PASSWORD, "new_password": "short"},
        headers=admin_headers,
    )
    assert weak.status_code == 422
    wrong = client.post(
        "/api/auth/password",
        json={"current_password": "nope", "new_password": "a-much-better-password"},
        headers=admin_headers,
    )
    assert wrong.status_code == 400
    ok = client.post(
        "/api/auth/password",
        json={"current_password": ADMIN_PASSWORD, "new_password": "a-much-better-password"},
        headers=admin_headers,
    )
    assert ok.status_code == 200
    # The old token is revoked; the returned one works.
    assert client.get("/api/auth/me", headers=admin_headers).status_code == 401
    new_headers = {"Authorization": f"Bearer {ok.json()['access_token']}"}
    assert client.get("/api/auth/me", headers=new_headers).status_code == 200
    login(client, "admin", "a-much-better-password")


def test_totp_enrolment_login_and_replay(client, admin_headers):
    setup = client.post("/api/auth/totp/setup", headers=admin_headers).json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/NimbusVPN:admin")
    assert setup["qr_svg"].startswith("data:image/svg+xml")
    totp = pyotp.TOTP(setup["secret"])

    assert (
        client.post(
            "/api/auth/totp/enable", json={"code": "000000"}, headers=admin_headers
        ).status_code
        == 400
    )
    enabled = client.post("/api/auth/totp/enable", json={"code": totp.now()}, headers=admin_headers)
    assert enabled.status_code == 200 and enabled.json()["totp_enabled"] is True

    missing = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    assert missing.status_code == 401 and missing.json()["detail"] == "totp_required"

    # The code used for enrolment cannot be replayed; the next time step's code is accepted.
    replay = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": ADMIN_PASSWORD, "totp_code": totp.now()},
    )
    assert replay.status_code == 401
    next_code = totp.at(time.time() + 30)
    login(client, "admin", ADMIN_PASSWORD, totp_code=next_code)


def test_verify_totp_window_and_replay():
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    now = 1_700_000_000
    step = verify_totp(secret, totp.at(now), last_step=0, now=now)
    assert step == now // 30
    assert verify_totp(secret, totp.at(now), last_step=step, now=now) is None
    assert verify_totp(secret, totp.at(now - 30), last_step=0, now=now) == step - 1
    assert verify_totp(secret, totp.at(now - 90), last_step=0, now=now) is None
    assert verify_totp(secret, "abc123", last_step=0, now=now) is None


def test_token_service_rejects_tampering():
    service = TokenService("s" * 40, 5)
    token = service.issue(7, 3)
    claims = service.verify(token)
    assert (claims.user_id, claims.token_version) == (7, 3)
    assert TokenService("t" * 40, 5).verify(token) is None
    assert service.verify(token[:-2] + "xx") is None


def test_disabled_user_cannot_log_in(client, admin_headers, user_headers):
    users = client.get("/api/admin/users", headers=admin_headers).json()
    alice = next(u for u in users if u["username"] == "alice")
    client.patch(f"/api/admin/users/{alice['id']}", json={"enabled": False}, headers=admin_headers)
    assert client.get("/api/auth/me", headers=user_headers).status_code == 401
    r = client.post("/api/auth/login", json={"username": "alice", "password": USER_PASSWORD})
    assert r.status_code == 403
