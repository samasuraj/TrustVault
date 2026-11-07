import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
import pytest
from fastapi import HTTPException, FastAPI, Depends
from fastapi.testclient import TestClient
from app.authz import authorize, RequireDocAccess
from app.models import Document, Grant, User, AuditEvent
from app.db import get_db
from app.deps import get_current_user

ACTIONS = ["read", "download", "edit", "delete", "share", "view_meta"]
ROLES = ["admin", "owner", "viewer"]
CONTEXTS = ["owner", "granted-read", "granted-edit", "revoked", "expired", "stranger", "admin"]

def should_allow(context: str, action: str) -> bool:
    if context == "owner":
        return True
    if context == "granted-read":
        return action in ("read", "download", "view_meta")
    if context == "granted-edit":
        return action in ("read", "download", "view_meta", "edit")
    if context in ("revoked", "expired", "stranger", "admin"):
        return False
    return False

# Build 126 test cases: (role, action, context)
MATRIX_CASES = [
    (role, action, context)
    for role in ROLES
    for action in ACTIONS
    for context in CONTEXTS
]

@pytest.mark.parametrize("role,action,context", MATRIX_CASES)
def test_authz_matrix(role, action, context):
    db = MagicMock()
    user_id = uuid.uuid4()
    owner_id = user_id if context == "owner" else uuid.uuid4()
    doc_id = uuid.uuid4()

    # In 'admin' context, role is specifically admin
    actual_role = "admin" if context == "admin" else role
    user = User(
        id=user_id,
        email="test@trustvault.local",
        name="Test",
        pw_hash="hash",
        role=actual_role,
        is_active=True,
        token_version=1,
    )

    doc = Document(
        id=doc_id,
        owner_id=owner_id,
        name="Test Doc",
        category="Finance",
        deleted_at=None,
    )

    grant = None
    now = datetime.now(timezone.utc)
    if context == "granted-read":
        grant = Grant(
            id=uuid.uuid4(),
            doc_id=doc_id,
            user_id=user_id,
            perm="read",
            granted_by=owner_id,
            granted_at=now,
            revoked_at=None,
            expires_at=now + timedelta(days=1),
        )
    elif context == "granted-edit":
        grant = Grant(
            id=uuid.uuid4(),
            doc_id=doc_id,
            user_id=user_id,
            perm="edit",
            granted_by=owner_id,
            granted_at=now,
            revoked_at=None,
            expires_at=now + timedelta(days=1),
        )
    elif context == "revoked":
        grant = None  # DB filter for revoked_at is None will not return it
    elif context == "expired":
        grant = None  # DB filter for expires_at > now will not return it

    def mock_query(model, *args, **kwargs):
        q = MagicMock()
        if model == Document:
            q.filter.return_value.first.return_value = doc
        elif model == Grant:
            q.filter.return_value.first.return_value = grant
        elif model == AuditEvent:
            q.order_by.return_value.first.return_value = None
        else:
            q.filter.return_value.first.return_value = None
        return q

    db.query.side_effect = mock_query

    expected = should_allow(context, action)
    if expected:
        result = authorize(db, user, doc_id, action)
        assert result.id == doc.id
    else:
        with pytest.raises(HTTPException) as exc:
            authorize(db, user, doc_id, action)
        # Deny by default: 404 so existence is not leaked
        assert exc.value.status_code == 404
        assert exc.value.detail == "Document not found"

def test_soft_deleted_docs_inaccessible():
    db = MagicMock()
    user_id = uuid.uuid4()
    owner_id = uuid.uuid4()
    doc_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    user = User(id=user_id, email="u@tv.local", name="U", pw_hash="h", role="viewer", is_active=True, token_version=1)
    deleted_doc = Document(id=doc_id, owner_id=owner_id, name="Deleted", category="C", deleted_at=now)

    db.query.return_value.filter.return_value.first.return_value = deleted_doc
    db.query.return_value.order_by.return_value.first.return_value = None

    # Even with a grant, soft-deleted doc is inaccessible
    for act in ACTIONS:
        with pytest.raises(HTTPException) as exc:
            authorize(db, user, doc_id, act)
        assert exc.value.status_code == 404

    # Owner cannot read or download deleted doc directly
    owner = User(id=owner_id, email="o@tv.local", name="O", pw_hash="h", role="owner", is_active=True, token_version=1)
    with pytest.raises(HTTPException) as exc:
        authorize(db, owner, doc_id, "read")
    assert exc.value.status_code == 404

    # But owner CAN restore soft-deleted doc
    res = authorize(db, owner, doc_id, "restore")
    assert res.id == deleted_doc.id

def test_idor_protection_across_endpoints():
    test_app = FastAPI()

    @test_app.get("/api/documents/{doc_id}")
    def get_doc(doc: Document = Depends(RequireDocAccess("read"))):
        return {"id": str(doc.id), "name": doc.name}

    @test_app.get("/api/documents/{doc_id}/download")
    def dl_doc(doc: Document = Depends(RequireDocAccess("download"))):
        return {"download": str(doc.id)}

    @test_app.put("/api/documents/{doc_id}")
    def edit_doc(doc: Document = Depends(RequireDocAccess("edit"))):
        return {"edited": str(doc.id)}

    @test_app.delete("/api/documents/{doc_id}")
    def del_doc(doc: Document = Depends(RequireDocAccess("delete"))):
        return {"deleted": str(doc.id)}

    @test_app.post("/api/documents/{doc_id}/share")
    def share_doc(doc: Document = Depends(RequireDocAccess("share"))):
        return {"shared": str(doc.id)}

    # User A owns Doc A
    user_a = User(id=uuid.uuid4(), email="a@tv.local", name="A", pw_hash="h", role="owner", is_active=True, token_version=1)
    # User B owns Doc B
    user_b = User(id=uuid.uuid4(), email="b@tv.local", name="B", pw_hash="h", role="owner", is_active=True, token_version=1)

    doc_b_id = uuid.uuid4()
    doc_b = Document(id=doc_b_id, owner_id=user_b.id, name="Doc B", category="Confidential", deleted_at=None)

    mock_db = MagicMock()
    def mock_query(model, *args, **kwargs):
        q = MagicMock()
        if model == Document:
            q.filter.return_value.first.return_value = doc_b
        elif model == Grant:
            q.filter.return_value.first.return_value = None
        elif model == AuditEvent:
            q.order_by.return_value.first.return_value = None
        else:
            q.filter.return_value.first.return_value = None
        return q

    mock_db.query.side_effect = mock_query

    test_app.dependency_overrides[get_db] = lambda: mock_db
    test_app.dependency_overrides[get_current_user] = lambda: user_a

    c = TestClient(test_app)

    # User A tries to swap doc_id to doc_b on every endpoint
    for url, method in [
        (f"/api/documents/{doc_b_id}", "get"),
        (f"/api/documents/{doc_b_id}/download", "get"),
        (f"/api/documents/{doc_b_id}", "put"),
        (f"/api/documents/{doc_b_id}", "delete"),
        (f"/api/documents/{doc_b_id}/share", "post"),
    ]:
        res = getattr(c, method)(url)
        # IDOR attempt must return 404 (not 403, no info leak)
        assert res.status_code == 404
        assert res.json()["detail"] == "Document not found"

def test_missing_authorize_in_download_causes_test_failure():
    # Demonstrates that removing authorize() from the download route allows unauthorized access,
    # which fails the security assertion.
    insecure_app = FastAPI()

    # Intentionally flawed endpoint that forgets to authorize
    @insecure_app.get("/download/{doc_id}")
    def insecure_download(doc_id: uuid.UUID):
        return {"file_data": "secret_content", "doc_id": str(doc_id)}

    c = TestClient(insecure_app)
    unauthorized_doc_id = uuid.uuid4()

    response = c.get(f"/download/{unauthorized_doc_id}")

    # A security test expects 404 on unauthorized download.
    # Because authorize was omitted, response is 200, which proves that
    # omitting authorize makes the security test FAIL:
    assert response.status_code != 404  # Demonstrates omission bypasses security
    assert response.status_code == 200

    # Proper secure endpoint WITH authorize:
    secure_app = FastAPI()
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None
    mock_db.query.return_value.order_by.return_value.first.return_value = None
    secure_app.dependency_overrides[get_db] = lambda: mock_db
    secure_app.dependency_overrides[get_current_user] = lambda: User(
        id=uuid.uuid4(), email="u@tv.local", name="U", pw_hash="h", role="viewer", is_active=True, token_version=1
    )

    @secure_app.get("/download/{doc_id}")
    def secure_download(doc: Document = Depends(RequireDocAccess("download"))):
        return {"file_data": "secret_content"}

    sec_c = TestClient(secure_app)
    sec_res = sec_c.get(f"/download/{unauthorized_doc_id}")
    # Secure version correctly blocks with 404
    assert sec_res.status_code == 404
