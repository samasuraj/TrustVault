import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db import get_db
from app.models import User
from app.security import hash_pw, create_access_token, COOKIE_ACCESS_NAME, COOKIE_CSRF_NAME
from app.deps import reset_rate_limiter

@pytest.fixture(autouse=True)
def clean_rate_limit():
    reset_rate_limiter()

def test_login_success():
    mock_db = MagicMock()
    app.dependency_overrides[get_db] = lambda: mock_db
    c = TestClient(app)

    u_id = uuid.uuid4()
    raw_pw = "ValidPass123!"
    user = User(
        id=u_id,
        email="alice@trustvault.local",
        name="Alice",
        pw_hash=hash_pw(raw_pw),
        role="owner",
        is_active=True,
        token_version=1,
        failed_logins=0,
        locked_until=None,
    )
    mock_db.query.return_value.filter.return_value.first.return_value = user

    res = c.post("/api/auth/login", json={"email": "alice@trustvault.local", "password": raw_pw})
    assert res.status_code == 200
    data = res.json()
    assert data["user"]["email"] == "alice@trustvault.local"
    assert "csrf_token" in data
    assert COOKIE_ACCESS_NAME in res.cookies
    assert COOKIE_CSRF_NAME in res.cookies
    assert user.failed_logins == 0

    app.dependency_overrides.clear()

def test_login_bad_password():
    mock_db = MagicMock()
    app.dependency_overrides[get_db] = lambda: mock_db
    c = TestClient(app)

    user = User(
        id=uuid.uuid4(),
        email="alice@trustvault.local",
        name="Alice",
        pw_hash=hash_pw("CorrectPassword123!"),
        role="owner",
        is_active=True,
        token_version=1,
        failed_logins=0,
        locked_until=None,
    )
    mock_db.query.return_value.filter.return_value.first.return_value = user

    res = c.post("/api/auth/login", json={"email": "alice@trustvault.local", "password": "WrongPassword"})
    assert res.status_code == 401
    assert user.failed_logins == 1

    app.dependency_overrides.clear()

def test_lockout_after_five_failed_attempts():
    mock_db = MagicMock()
    app.dependency_overrides[get_db] = lambda: mock_db
    c = TestClient(app)

    user = User(
        id=uuid.uuid4(),
        email="locked@trustvault.local",
        name="Lock Test",
        pw_hash=hash_pw("Password123!"),
        role="viewer",
        is_active=True,
        token_version=1,
        failed_logins=4,
        locked_until=None,
    )
    mock_db.query.return_value.filter.return_value.first.return_value = user

    # 5th failed attempt triggers lockout
    res = c.post("/api/auth/login", json={"email": "locked@trustvault.local", "password": "BadPassword"})
    assert res.status_code == 401
    assert user.failed_logins == 5
    assert user.locked_until is not None

    # Subsequent attempt is locked out with 403
    res_locked = c.post("/api/auth/login", json={"email": "locked@trustvault.local", "password": "Password123!"})
    assert res_locked.status_code == 403
    assert "locked" in res_locked.json()["detail"].lower()

    app.dependency_overrides.clear()

def test_disabled_user_login_rejected():
    mock_db = MagicMock()
    app.dependency_overrides[get_db] = lambda: mock_db
    c = TestClient(app)

    user = User(
        id=uuid.uuid4(),
        email="disabled@trustvault.local",
        name="Disabled",
        pw_hash=hash_pw("Password123!"),
        role="viewer",
        is_active=False,
        token_version=1,
        failed_logins=0,
    )
    mock_db.query.return_value.filter.return_value.first.return_value = user

    res = c.post("/api/auth/login", json={"email": "disabled@trustvault.local", "password": "Password123!"})
    assert res.status_code == 401
    assert "disabled" in res.json()["detail"].lower()

    app.dependency_overrides.clear()

def test_disabled_user_token_rejected_on_request():
    mock_db = MagicMock()
    app.dependency_overrides[get_db] = lambda: mock_db
    c = TestClient(app)

    u_id = uuid.uuid4()
    tok = create_access_token(str(u_id), "viewer", token_ver=1)

    # In DB the user is disabled
    user = User(
        id=u_id,
        email="user@trustvault.local",
        name="User",
        pw_hash="hash",
        role="viewer",
        is_active=False,
        token_version=1,
    )
    mock_db.query.return_value.filter.return_value.first.return_value = user

    c.cookies.set(COOKIE_ACCESS_NAME, tok)
    res = c.get("/api/auth/me")
    assert res.status_code == 401
    assert "disabled" in res.json()["detail"].lower()

    app.dependency_overrides.clear()

def test_bumped_token_version_rejects_old_token():
    mock_db = MagicMock()
    app.dependency_overrides[get_db] = lambda: mock_db
    c = TestClient(app)

    u_id = uuid.uuid4()
    # Token issued with token_version = 1
    tok = create_access_token(str(u_id), "viewer", token_ver=1)

    # User in DB was bumped to token_version = 2
    user = User(
        id=u_id,
        email="user@trustvault.local",
        name="User",
        pw_hash="hash",
        role="viewer",
        is_active=True,
        token_version=2,
    )
    mock_db.query.return_value.filter.return_value.first.return_value = user

    c.cookies.set(COOKIE_ACCESS_NAME, tok)
    res = c.get("/api/auth/me")
    assert res.status_code == 401
    assert "revoked" in res.json()["detail"].lower()

    app.dependency_overrides.clear()

def test_rate_limiting_on_login():
    mock_db = MagicMock()
    app.dependency_overrides[get_db] = lambda: mock_db
    c = TestClient(app)
    mock_db.query.return_value.filter.return_value.first.return_value = None

    # First 10 attempts pass to authentication check (401 not found)
    for _ in range(10):
        res = c.post("/api/auth/login", json={"email": "nonexistent@trustvault.local", "password": "pass"})
        assert res.status_code == 401

    # 11th attempt is blocked by rate limiter with 429
    res_rl = c.post("/api/auth/login", json={"email": "nonexistent@trustvault.local", "password": "pass"})
    assert res_rl.status_code == 429
    assert "rate limit" in res_rl.json()["detail"].lower()

    app.dependency_overrides.clear()

def test_admin_registration_and_csrf_requirement():
    mock_db = MagicMock()
    app.dependency_overrides[get_db] = lambda: mock_db
    c = TestClient(app)

    admin_id = uuid.uuid4()
    admin = User(
        id=admin_id,
        email="admin@trustvault.local",
        name="Admin",
        pw_hash="hash",
        role="admin",
        is_active=True,
        token_version=1,
    )
    mock_db.query.return_value.filter.return_value.first.side_effect = [admin, None]

    admin_tok = create_access_token(str(admin_id), "admin", token_ver=1)
    c.cookies.set(COOKIE_ACCESS_NAME, admin_tok)

    # Without CSRF token header -> 403
    payload = {"email": "newuser@trustvault.local", "name": "New User", "password": "NewUserPassword123!", "role": "viewer"}
    res_nocsrf = c.post("/api/auth/register", json=payload)
    assert res_nocsrf.status_code == 403

    # With matching CSRF cookie and header -> 200
    mock_db.query.return_value.filter.return_value.first.side_effect = [admin, None]
    c.cookies.set(COOKIE_CSRF_NAME, "test-csrf-token")
    headers = {"X-CSRF-Token": "test-csrf-token"}
    res_ok = c.post("/api/auth/register", json=payload, headers=headers)
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert data["email"] == "newuser@trustvault.local"
    assert data["role"] == "viewer"

    app.dependency_overrides.clear()

def test_viewer_cannot_register():
    mock_db = MagicMock()
    app.dependency_overrides[get_db] = lambda: mock_db
    c = TestClient(app)

    viewer_id = uuid.uuid4()
    viewer = User(
        id=viewer_id,
        email="viewer@trustvault.local",
        name="Viewer",
        pw_hash="hash",
        role="viewer",
        is_active=True,
        token_version=1,
    )
    mock_db.query.return_value.filter.return_value.first.return_value = viewer

    viewer_tok = create_access_token(str(viewer_id), "viewer", token_ver=1)
    c.cookies.set(COOKIE_ACCESS_NAME, viewer_tok)
    c.cookies.set(COOKIE_CSRF_NAME, "test-csrf")
    headers = {"X-CSRF-Token": "test-csrf"}

    payload = {"email": "illegal@trustvault.local", "name": "Illegal", "password": "Password123!", "role": "viewer"}
    res = c.post("/api/auth/register", json=payload, headers=headers)
    assert res.status_code == 403
    assert "admin" in res.json()["detail"].lower()

    app.dependency_overrides.clear()
