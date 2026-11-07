import io
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db import get_db
from app.deps import get_current_user, get_optional_current_user
from app.models import Document, DocVersion, Grant, User, DownloadToken, AuditEvent
from app.storage import encrypt_and_store
from app.config import cfg

@pytest.fixture(autouse=True)
def setup_temp_storage(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setattr(cfg, "storage_dir", tmpdir)
        yield tmpdir

class StatefulDB:
    def __init__(self, users=None, docs=None, versions=None, grants=None, tokens=None):
        self.users = {u.id: u for u in (users or [])}
        self.users_by_email = {u.email.lower(): u for u in (users or [])}
        self.docs = {d.id: d for d in (docs or [])}
        self.versions = {v.id: v for v in (versions or [])}
        self.grants = {g.id: g for g in (grants or [])}
        self.tokens = {t.id: t for t in (tokens or [])}
        self.audit_events = []

    def add(self, obj):
        if isinstance(obj, User):
            self.users[obj.id] = obj
            self.users_by_email[obj.email.lower()] = obj
        elif isinstance(obj, Document):
            self.docs[obj.id] = obj
        elif isinstance(obj, DocVersion):
            self.versions[obj.id] = obj
        elif isinstance(obj, Grant):
            self.grants[obj.id] = obj
        elif isinstance(obj, DownloadToken):
            self.tokens[obj.id] = obj
        elif isinstance(obj, AuditEvent):
            obj.id = len(self.audit_events) + 1
            self.audit_events.append(obj)

    def commit(self):
        pass

    def flush(self):
        pass

    def refresh(self, obj):
        pass

    def query(self, *models):
        model = models[0]
        q = MagicMock()

        if model == User:
            def filter_user(*args, **kwargs):
                fq = MagicMock()
                def first_user():
                    for arg in args:
                        s = str(arg)
                        if "users.email" in s:
                            val = arg.right.value if hasattr(arg, "right") else None
                            if val:
                                return self.users_by_email.get(str(val).lower())
                        if "users.id" in s:
                            val = arg.right.value if hasattr(arg, "right") else None
                            if val:
                                return self.users.get(val)
                    return list(self.users.values())[0] if self.users else None
                fq.first.side_effect = first_user
                return fq
            q.filter.side_effect = filter_user

        elif model == Document:
            def filter_doc(*args, **kwargs):
                fq = MagicMock()
                def first_doc():
                    for arg in args:
                        if hasattr(arg, "right"):
                            val = arg.right.value
                            if val in self.docs:
                                return self.docs[val]
                    return list(self.docs.values())[0] if self.docs else None
                fq.first.side_effect = first_doc
                return fq
            q.filter.side_effect = filter_doc

        elif model == DocVersion:
            def filter_ver(*args, **kwargs):
                fq = MagicMock()
                def first_ver():
                    for arg in args:
                        if hasattr(arg, "right"):
                            val = arg.right.value
                            if val in self.versions:
                                return self.versions[val]
                    return list(self.versions.values())[0] if self.versions else None
                fq.first.side_effect = first_ver
                return fq
            q.filter.side_effect = filter_ver

        elif model == Grant:
            if len(models) == 2 and models[1] == User.email:
                jq = MagicMock()
                fq = MagicMock()
                oq = MagicMock()
                def all_grants():
                    now = datetime.now(timezone.utc)
                    res = []
                    for g in sorted(self.grants.values(), key=lambda x: x.granted_at or now, reverse=True):
                        u = self.users.get(g.user_id)
                        email = u.email if u else "unknown"
                        res.append((g, email))
                    return res
                oq.all.side_effect = all_grants
                fq.order_by.return_value = oq
                jq.filter.return_value = fq
                q.join.return_value = jq
                return q

            def filter_grant(*args, **kwargs):
                fq = MagicMock()
                now = datetime.now(timezone.utc)

                def all_grants():
                    active = []
                    for g in self.grants.values():
                        if g.revoked_at is None:
                            active.append(g)
                    return active

                def first_grant():
                    # 1. Check if looking for specific grant id
                    for arg in args:
                        s = str(arg)
                        if "grants.id" in s and hasattr(arg, "right"):
                            gid = arg.right.value
                            return self.grants.get(gid)

                    # 2. Check for active grant for doc and user
                    target_uid = None
                    target_docid = None
                    for arg in args:
                        s = str(arg)
                        if "grants.user_id" in s and hasattr(arg, "right"):
                            target_uid = arg.right.value
                        if "grants.doc_id" in s and hasattr(arg, "right"):
                            target_docid = arg.right.value

                    for g in self.grants.values():
                        if target_uid and g.user_id != target_uid:
                            continue
                        if target_docid and g.doc_id != target_docid:
                            continue
                        if g.revoked_at is None:
                            if g.expires_at is None or g.expires_at > now:
                                return g
                    return None

                def order_by_grant(*args, **kwargs):
                    oq = MagicMock()
                    def first_ordered():
                        return list(self.grants.values())[-1] if self.grants else None
                    oq.first.side_effect = first_ordered
                    return oq

                fq.all.side_effect = all_grants
                fq.first.side_effect = first_grant
                fq.order_by.side_effect = order_by_grant
                return fq
            q.filter.side_effect = filter_grant

        elif model == DownloadToken:
            def filter_token(*args, **kwargs):
                fq = MagicMock()
                def first_tok():
                    for arg in args:
                        s = str(arg)
                        if "download_tokens.id" in s and hasattr(arg, "right"):
                            return self.tokens.get(arg.right.value)
                    return list(self.tokens.values())[0] if self.tokens else None

                def update_tok(values):
                    now = datetime.now(timezone.utc)
                    cnt = 0
                    for t in self.tokens.values():
                        if t.used_at is None:
                            t.used_at = values.get("used_at", now)
                            cnt += 1
                    return cnt

                fq.first.side_effect = first_tok
                fq.update.side_effect = update_tok
                return fq
            q.filter.side_effect = filter_token

        elif model == AuditEvent:
            oq = MagicMock()
            oq.first.side_effect = lambda: self.audit_events[-1] if self.audit_events else None
            q.order_by.return_value = oq

        return q


def test_grant_download_revoke_immediate_failure_and_tokens():
    owner = User(id=uuid.uuid4(), email="owner@tv.local", name="Owner", pw_hash="h", role="owner", is_active=True, token_version=1)
    viewer = User(id=uuid.uuid4(), email="viewer@tv.local", name="Viewer", pw_hash="h", role="viewer", is_active=True, token_version=1)

    raw_file = b"%PDF-1.4 Confidential Contract"
    storage_key = uuid.uuid4()
    size, sha = encrypt_and_store(raw_file, storage_key)

    doc_id = uuid.uuid4()
    ver_id = uuid.uuid4()
    doc = Document(id=doc_id, owner_id=owner.id, name="Contract.pdf", category="Legal", current_version_id=ver_id, deleted_at=None)
    ver = DocVersion(id=ver_id, doc_id=doc_id, version_no=1, storage_key=storage_key, size=size, sha256=sha, mime="application/pdf", uploaded_by=owner.id)

    db = StatefulDB(users=[owner, viewer], docs=[doc], versions=[ver])
    app.dependency_overrides[get_db] = lambda: db

    c = TestClient(app)
    c.cookies.set("tv_csrf", "csrf-token")
    headers = {"X-CSRF-Token": "csrf-token"}

    # 1. Viewer initially gets 404 (Security Rule 2: Deny by default)
    app.dependency_overrides[get_current_user] = lambda: viewer
    res = c.get(f"/api/documents/{doc_id}/download")
    assert res.status_code == 404

    # 2. Owner grants 'read' permission to viewer
    app.dependency_overrides[get_current_user] = lambda: owner
    grant_payload = {"user_email": "viewer@tv.local", "perm": "read"}
    res = c.post(f"/api/documents/{doc_id}/grants", json=grant_payload, headers=headers)
    assert res.status_code == 201
    g_data = res.json()
    assert g_data["perm"] == "read"
    assert g_data["user_email"] == "viewer@tv.local"
    grant_id = uuid.UUID(g_data["id"])

    # 3. Viewer download works with active grant
    app.dependency_overrides[get_current_user] = lambda: viewer
    res = c.get(f"/api/documents/{doc_id}/download")
    assert res.status_code == 200
    assert res.content == raw_file

    # 4. Viewer issues a single-use download token
    res = c.post(f"/api/documents/{doc_id}/download-token", headers=headers)
    assert res.status_code == 200
    tok_data = res.json()
    tok_id = tok_data["token"]
    assert "download_url" in tok_data

    # 5. Token download works without active user session
    app.dependency_overrides.pop(get_current_user, None)
    res = c.get(f"/api/documents/{doc_id}/download?token={tok_id}")
    assert res.status_code == 200
    assert res.content == raw_file

    # 6. Second redemption fails (single-use token)
    res = c.get(f"/api/documents/{doc_id}/download?token={tok_id}")
    assert res.status_code == 404

    # 7. Issue a second token to test revocation invalidation
    app.dependency_overrides[get_current_user] = lambda: viewer
    res = c.post(f"/api/documents/{doc_id}/download-token", headers=headers)
    assert res.status_code == 200
    second_tok_id = res.json()["token"]

    # 8. Owner revokes grant
    app.dependency_overrides[get_current_user] = lambda: owner
    res = c.delete(f"/api/documents/{doc_id}/grants/{grant_id}", headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "revoked"

    # 9. Viewer same session download immediately fails with 404
    app.dependency_overrides[get_current_user] = lambda: viewer
    res = c.get(f"/api/documents/{doc_id}/download")
    assert res.status_code == 404

    # 10. Old token immediately fails with 404
    app.dependency_overrides.pop(get_current_user, None)
    res = c.get(f"/api/documents/{doc_id}/download?token={second_tok_id}")
    assert res.status_code == 404

    app.dependency_overrides.clear()


def test_expired_grant_fails():
    owner = User(id=uuid.uuid4(), email="owner@tv.local", name="Owner", pw_hash="h", role="owner", is_active=True, token_version=1)
    viewer = User(id=uuid.uuid4(), email="viewer@tv.local", name="Viewer", pw_hash="h", role="viewer", is_active=True, token_version=1)

    raw_file = b"%PDF-1.4 Expired Document Test"
    storage_key = uuid.uuid4()
    size, sha = encrypt_and_store(raw_file, storage_key)

    doc_id = uuid.uuid4()
    ver_id = uuid.uuid4()
    doc = Document(id=doc_id, owner_id=owner.id, name="Expired.pdf", category="Legal", current_version_id=ver_id, deleted_at=None)
    ver = DocVersion(id=ver_id, doc_id=doc_id, version_no=1, storage_key=storage_key, size=size, sha256=sha, mime="application/pdf", uploaded_by=owner.id)

    # Grant with past expiry
    past_expiry = datetime.now(timezone.utc) - timedelta(minutes=10)
    expired_grant = Grant(
        id=uuid.uuid4(),
        doc_id=doc_id,
        user_id=viewer.id,
        perm="read",
        granted_by=owner.id,
        granted_at=past_expiry - timedelta(days=1),
        revoked_at=None,
        expires_at=past_expiry,
    )

    db = StatefulDB(users=[owner, viewer], docs=[doc], versions=[ver], grants=[expired_grant])
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: viewer

    c = TestClient(app)
    # GET /documents/{id} -> 404
    res = c.get(f"/api/documents/{doc_id}")
    assert res.status_code == 404

    # GET /documents/{id}/download -> 404
    res = c.get(f"/api/documents/{doc_id}/download")
    assert res.status_code == 404

    app.dependency_overrides.clear()


def test_viewer_cannot_grant_or_revoke():
    owner = User(id=uuid.uuid4(), email="owner@tv.local", name="Owner", pw_hash="h", role="owner", is_active=True, token_version=1)
    viewer = User(id=uuid.uuid4(), email="viewer@tv.local", name="Viewer", pw_hash="h", role="viewer", is_active=True, token_version=1)
    other = User(id=uuid.uuid4(), email="other@tv.local", name="Other", pw_hash="h", role="viewer", is_active=True, token_version=1)

    doc_id = uuid.uuid4()
    doc = Document(id=doc_id, owner_id=owner.id, name="Confidential.pdf", category="Legal", current_version_id=None, deleted_at=None)
    grant_id = uuid.uuid4()
    grant = Grant(id=grant_id, doc_id=doc_id, user_id=viewer.id, perm="read", granted_by=owner.id, granted_at=datetime.now(timezone.utc), revoked_at=None, expires_at=None)

    db = StatefulDB(users=[owner, viewer, other], docs=[doc], grants=[grant])
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: viewer

    c = TestClient(app)
    c.cookies.set("tv_csrf", "csrf-token")
    headers = {"X-CSRF-Token": "csrf-token"}

    # Viewer attempts to grant access to 'other' -> 404 (Security Rule 2: Deny by default)
    res = c.post(f"/api/documents/{doc_id}/grants", json={"user_email": "other@tv.local", "perm": "read"}, headers=headers)
    assert res.status_code == 404

    # Viewer attempts to revoke grant -> 404
    res = c.delete(f"/api/documents/{doc_id}/grants/{grant_id}", headers=headers)
    assert res.status_code == 404

    # Viewer attempts to list grants -> 404
    res = c.get(f"/api/documents/{doc_id}/grants")
    assert res.status_code == 404

    app.dependency_overrides.clear()


def test_owner_isolation_cannot_touch_other_owner_docs():
    owner_a = User(id=uuid.uuid4(), email="ownera@tv.local", name="Owner A", pw_hash="h", role="owner", is_active=True, token_version=1)
    owner_b = User(id=uuid.uuid4(), email="ownerb@tv.local", name="Owner B", pw_hash="h", role="owner", is_active=True, token_version=1)
    viewer = User(id=uuid.uuid4(), email="viewer@tv.local", name="Viewer", pw_hash="h", role="viewer", is_active=True, token_version=1)

    doc_a_id = uuid.uuid4()
    doc_a = Document(id=doc_a_id, owner_id=owner_a.id, name="DocA.pdf", category="General", current_version_id=None, deleted_at=None)

    db = StatefulDB(users=[owner_a, owner_b, viewer], docs=[doc_a])
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: owner_b

    c = TestClient(app)
    c.cookies.set("tv_csrf", "csrf-token")
    headers = {"X-CSRF-Token": "csrf-token"}

    # Owner B cannot grant access on Doc A -> 404
    res = c.post(f"/api/documents/{doc_a_id}/grants", json={"user_email": "viewer@tv.local", "perm": "read"}, headers=headers)
    assert res.status_code == 404

    # Owner B cannot view grants of Doc A -> 404
    res = c.get(f"/api/documents/{doc_a_id}/grants")
    assert res.status_code == 404

    # Owner B cannot issue download token on Doc A -> 404
    res = c.post(f"/api/documents/{doc_a_id}/download-token", headers=headers)
    assert res.status_code == 404

    # Owner B cannot download Doc A -> 404
    res = c.get(f"/api/documents/{doc_a_id}/download")
    assert res.status_code == 404

    app.dependency_overrides.clear()


def test_grants_listing_and_input_validations():
    owner = User(id=uuid.uuid4(), email="owner@tv.local", name="Owner", pw_hash="h", role="owner", is_active=True, token_version=1)
    viewer = User(id=uuid.uuid4(), email="viewer@tv.local", name="Viewer", pw_hash="h", role="viewer", is_active=True, token_version=1)

    doc_id = uuid.uuid4()
    doc = Document(id=doc_id, owner_id=owner.id, name="Doc.pdf", category="General", current_version_id=None, deleted_at=None)

    db = StatefulDB(users=[owner, viewer], docs=[doc])
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: owner

    c = TestClient(app)
    c.cookies.set("tv_csrf", "csrf-token")
    headers = {"X-CSRF-Token": "csrf-token"}

    # 1. Invalid perm -> 400
    res = c.post(f"/api/documents/{doc_id}/grants", json={"user_email": "viewer@tv.local", "perm": "superuser"}, headers=headers)
    assert res.status_code == 400

    # 2. Non-existent email -> 404
    res = c.post(f"/api/documents/{doc_id}/grants", json={"user_email": "ghost@tv.local", "perm": "read"}, headers=headers)
    assert res.status_code == 404

    # 3. Valid grant creation
    res = c.post(f"/api/documents/{doc_id}/grants", json={"user_email": "viewer@tv.local", "perm": "read"}, headers=headers)
    assert res.status_code == 201
    g_id = res.json()["id"]

    # 4. List grants
    res = c.get(f"/api/documents/{doc_id}/grants")
    assert res.status_code == 200
    grants = res.json()
    assert len(grants) == 1
    assert grants[0]["user_email"] == "viewer@tv.local"

    # 5. Revoke non-existent grant -> 404
    fake_gid = uuid.uuid4()
    res = c.delete(f"/api/documents/{doc_id}/grants/{fake_gid}", headers=headers)
    assert res.status_code == 404

    # 6. Revoke valid grant -> 200
    res = c.delete(f"/api/documents/{doc_id}/grants/{g_id}", headers=headers)
    assert res.status_code == 200

    app.dependency_overrides.clear()


def test_expired_download_token_fails():
    owner = User(id=uuid.uuid4(), email="owner@tv.local", name="Owner", pw_hash="h", role="owner", is_active=True, token_version=1)
    viewer = User(id=uuid.uuid4(), email="viewer@tv.local", name="Viewer", pw_hash="h", role="viewer", is_active=True, token_version=1)

    raw_file = b"%PDF-1.4 Token Expired Content"
    storage_key = uuid.uuid4()
    size, sha = encrypt_and_store(raw_file, storage_key)

    doc_id = uuid.uuid4()
    ver_id = uuid.uuid4()
    doc = Document(id=doc_id, owner_id=owner.id, name="Doc.pdf", category="General", current_version_id=ver_id, deleted_at=None)
    ver = DocVersion(id=ver_id, doc_id=doc_id, version_no=1, storage_key=storage_key, size=size, sha256=sha, mime="application/pdf", uploaded_by=owner.id)

    grant = Grant(id=uuid.uuid4(), doc_id=doc_id, user_id=viewer.id, perm="read", granted_by=owner.id, granted_at=datetime.now(timezone.utc), revoked_at=None, expires_at=None)

    # Expired token (created in the past, expires_at in the past)
    past = datetime.now(timezone.utc) - timedelta(seconds=120)
    tok = DownloadToken(id=uuid.uuid4(), doc_id=doc_id, user_id=viewer.id, expires_at=past, used_at=None)

    db = StatefulDB(users=[owner, viewer], docs=[doc], versions=[ver], grants=[grant], tokens=[tok])
    app.dependency_overrides[get_db] = lambda: db

    c = TestClient(app)
    # Redeeming expired token -> 404
    res = c.get(f"/api/documents/{doc_id}/download?token={tok.id}")
    assert res.status_code == 404

    app.dependency_overrides.clear()


def test_audit_trail_recorded_for_sharing_actions():
    owner = User(id=uuid.uuid4(), email="owner@tv.local", name="Owner", pw_hash="h", role="owner", is_active=True, token_version=1)
    viewer = User(id=uuid.uuid4(), email="viewer@tv.local", name="Viewer", pw_hash="h", role="viewer", is_active=True, token_version=1)

    raw_file = b"%PDF-1.4 Audit Trail Test"
    storage_key = uuid.uuid4()
    size, sha = encrypt_and_store(raw_file, storage_key)

    doc_id = uuid.uuid4()
    ver_id = uuid.uuid4()
    doc = Document(id=doc_id, owner_id=owner.id, name="Audited.pdf", category="General", current_version_id=ver_id, deleted_at=None)
    ver = DocVersion(id=ver_id, doc_id=doc_id, version_no=1, storage_key=storage_key, size=size, sha256=sha, mime="application/pdf", uploaded_by=owner.id)

    db = StatefulDB(users=[owner, viewer], docs=[doc], versions=[ver])
    app.dependency_overrides[get_db] = lambda: db

    c = TestClient(app)
    c.cookies.set("tv_csrf", "csrf-token")
    headers = {"X-CSRF-Token": "csrf-token"}

    # 1. Grant create
    app.dependency_overrides[get_current_user] = lambda: owner
    res = c.post(f"/api/documents/{doc_id}/grants", json={"user_email": "viewer@tv.local", "perm": "read"}, headers=headers)
    assert res.status_code == 201
    gid = res.json()["id"]

    # 2. Token issue
    app.dependency_overrides[get_current_user] = lambda: viewer
    res = c.post(f"/api/documents/{doc_id}/download-token", headers=headers)
    assert res.status_code == 200
    tok_id = res.json()["token"]

    # 3. Token redeem
    app.dependency_overrides.pop(get_current_user, None)
    res = c.get(f"/api/documents/{doc_id}/download?token={tok_id}")
    assert res.status_code == 200

    # 4. Grant revoke
    app.dependency_overrides[get_current_user] = lambda: owner
    res = c.delete(f"/api/documents/{doc_id}/grants/{gid}", headers=headers)
    assert res.status_code == 200

    # Verify audit actions
    actions = [e.action for e in db.audit_events]
    assert "grant_create" in actions
    assert "token_issue" in actions
    assert "token_redeem" in actions
    assert "grant_revoke" in actions

    app.dependency_overrides.clear()

