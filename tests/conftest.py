from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from nimbusvpn.config import Settings
from nimbusvpn.main import create_app

ADMIN_PASSWORD = "correct-horse-battery-staple"
USER_PASSWORD = "user-password-for-tests"


def make_settings(tmp_path, **overrides) -> Settings:
    values = {
        "secret_key": "test-secret-key-that-is-long-enough-1234567890",
        "data_dir": tmp_path / "data",
        "wg_backend": "dryrun",
        "reconcile_interval_seconds": 0,
        "admin_username": "admin",
        "admin_password": ADMIN_PASSWORD,
        "public_endpoint": "vpn.example.test",
        "login_ip_limit_per_window": 1000,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest.fixture
def settings(tmp_path) -> Settings:
    return make_settings(tmp_path)


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


def login(client: TestClient, username: str, password: str, **extra) -> dict[str, str]:
    response = client.post(
        "/api/auth/login", json={"username": username, "password": password, **extra}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def admin_headers(client) -> dict[str, str]:
    return login(client, "admin", ADMIN_PASSWORD)


@pytest.fixture
def user_headers(client, admin_headers) -> dict[str, str]:
    response = client.post(
        "/api/admin/users",
        json={"username": "alice", "password": USER_PASSWORD},
        headers=admin_headers,
    )
    assert response.status_code == 201, response.text
    return login(client, "alice", USER_PASSWORD)
