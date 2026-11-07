from fastapi.testclient import TestClient
from unittest.mock import MagicMock
from app.main import app
from app.db import get_db

def test_health_endpoint():
    mock_db = MagicMock()
    app.dependency_overrides[get_db] = lambda: mock_db
    c = TestClient(app)

    res = c.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["db"] is True

    api_res = c.get("/api/health")
    assert api_res.status_code == 200
    assert api_res.json()["status"] == "ok"

    app.dependency_overrides.clear()
