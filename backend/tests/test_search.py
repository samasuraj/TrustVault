import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db import get_db
from app.deps import get_current_user
from app.models import Document, DocVersion, Grant, User, AuditEvent
from app.authz import _hmac_hash

class MockDocQuery:
    def __init__(self, db, conditions=None):
        self.db = db
        self.conditions = list(conditions or [])

    def outerjoin(self, *args, **kwargs):
        return self

    def join(self, *args, **kwargs):
        return self

    def filter(self, *args):
        return MockDocQuery(self.db, self.conditions + list(args))

    def distinct(self):
        return self

    def all(self):
        now = datetime.now(timezone.utc)
        matched = []

        current_user_id = None
        filter_name = None
        filter_category = None
        filter_owner_id = None
        filter_owner_str = None
        filter_start_date = None
        filter_end_date = None

        for cond in self.conditions:
            sql = str(cond)
            params = cond.compile().params if hasattr(cond, "compile") else {}

            if "documents.owner_id =" in sql and "grants.user_id =" in sql:
                for k, v in params.items():
                    if "user_id" in k or "owner_id" in k:
                        current_user_id = v
                        break
            elif "documents.name" in sql:
                for k, v in params.items():
                    if "name" in k and isinstance(v, str):
                        filter_name = v.strip("%").lower()
            elif "documents.category" in sql:
                for k, v in params.items():
                    if "category" in k and isinstance(v, str):
                        filter_category = v.strip("%").lower()
            elif "documents.owner_id =" in sql:
                for k, v in params.items():
                    if "owner_id" in k:
                        filter_owner_id = v
            elif "users.email" in sql or "users.name" in sql:
                for k, v in params.items():
                    if isinstance(v, str):
                        filter_owner_str = v.strip("%").lower()
            elif "documents.created_at >=" in sql:
                for k, v in params.items():
                    if "created_at" in k:
                        filter_start_date = v
            elif "documents.created_at <=" in sql:
                for k, v in params.items():
                    if "created_at" in k:
                        filter_end_date = v

        for d in self.db.docs.values():
            if d.deleted_at is not None:
                continue

            if current_user_id:
                is_owner = (d.owner_id == current_user_id)
                has_grant = any(
                    g.doc_id == d.id and g.user_id == current_user_id and g.revoked_at is None
                    and (g.expires_at is None or g.expires_at > now)
                    for g in self.db.grants.values()
                )
                if not is_owner and not has_grant:
                    continue

            if filter_name and filter_name not in d.name.lower():
                continue

            if filter_category and filter_category not in d.category.lower():
                continue

            if filter_owner_id and d.owner_id != filter_owner_id:
                continue

            if filter_owner_str:
                owner = self.db.users.get(d.owner_id)
                o_email = owner.email.lower() if owner else ""
                o_name = owner.name.lower() if owner else ""
                if filter_owner_str not in o_email and filter_owner_str not in o_name:
                    continue

            if filter_start_date and d.created_at < filter_start_date:
                continue
            if filter_end_date and d.created_at > filter_end_date:
                continue

            matched.append(d)

        return matched


class SearchMockDB:
    def __init__(self, users=None, docs=None, versions=None, grants=None):
        self.users = {u.id: u for u in (users or [])}
        self.users_by_email = {u.email.lower(): u for u in (users or [])}
        self.docs = {d.id: d for d in (docs or [])}
        self.versions = {v.id: v for v in (versions or [])}
        self.grants = {g.id: g for g in (grants or [])}
        self.audit_events = []

    def add(self, obj):
        if isinstance(obj, AuditEvent):
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
        if model == Document:
            return MockDocQuery(self)

        q = MagicMock()
        if model == DocVersion:
            def filter_ver(*args, **kwargs):
                fq = MagicMock()
                target_doc_id = None
                for arg in args:
                    s = str(arg)
                    if "doc_versions.doc_id =" in s and hasattr(arg, "right"):
                        target_doc_id = arg.right.value
                    if "doc_versions.id =" in s and hasattr(arg, "right"):
                        vid = arg.right.value
                        return MagicMock(first=lambda: self.versions.get(vid))

                matched = [v for v in self.versions.values() if not target_doc_id or v.doc_id == target_doc_id]
                oq = MagicMock()
                oq.all.return_value = sorted(matched, key=lambda x: x.version_no, reverse=True)
                fq.order_by.return_value = oq
                fq.first.return_value = matched[0] if matched else None
                return fq
            q.filter.side_effect = filter_ver

        elif model == AuditEvent:
            oq = MagicMock()
            oq.with_for_update.return_value = oq
            oq.first.side_effect = lambda: self.audit_events[-1] if self.audit_events else None
            q.order_by.return_value = oq

        return q


def test_search_never_leaks_inaccessible_docs():
    """
    Test requirement: Permission filtering is part of the SQL WHERE clause,
    so results never include docs the user cannot see.
    Test that search never leaks names/counts of inaccessible docs.
    """
    now = datetime.now(timezone.utc)
    owner_a = User(id=uuid.uuid4(), email="alice@tv.local", name="Alice", pw_hash="h", role="owner", is_active=True, token_version=1)
    owner_b = User(id=uuid.uuid4(), email="bob@tv.local", name="Bob", pw_hash="h", role="owner", is_active=True, token_version=1)
    viewer_c = User(id=uuid.uuid4(), email="charlie@tv.local", name="Charlie", pw_hash="h", role="viewer", is_active=True, token_version=1)

    # Alice's docs
    doc_a1 = Document(
        id=uuid.uuid4(), owner_id=owner_a.id, name="Project Secret Phoenix.pdf",
        category="Strategy", created_at=now, deleted_at=None
    )
    doc_a2 = Document(
        id=uuid.uuid4(), owner_id=owner_a.id, name="Marketing 2026.pdf",
        category="Marketing", created_at=now, deleted_at=None
    )

    # Bob's doc
    doc_b1 = Document(
        id=uuid.uuid4(), owner_id=owner_b.id, name="Financial Budget.xlsx",
        category="Finance", created_at=now, deleted_at=None
    )

    # Alice shares doc_a2 with Bob, but NOT doc_a1
    grant = Grant(
        id=uuid.uuid4(), doc_id=doc_a2.id, user_id=owner_b.id, perm="read",
        granted_by=owner_a.id, granted_at=now, revoked_at=None, expires_at=None
    )

    db = SearchMockDB(
        users=[owner_a, owner_b, viewer_c],
        docs=[doc_a1, doc_a2, doc_b1],
        grants=[grant],
    )
    app.dependency_overrides[get_db] = lambda: db

    c = TestClient(app)

    # 1. Bob searches by name "Secret" -> Alice's inaccessible doc MUST NOT leak
    app.dependency_overrides[get_current_user] = lambda: owner_b
    res = c.get("/search?name=Secret")
    assert res.status_code == 200
    results = res.json()
    assert len(results) == 0  # Count is strictly 0
    assert not any("Secret" in d["name"] for d in results)

    # 2. Bob searches by category "Strategy" -> Inaccessible doc MUST NOT leak
    res = c.get("/search?category=Strategy")
    assert res.status_code == 200
    results = res.json()
    assert len(results) == 0

    # 3. Bob searches with no filters -> Can only see his own doc (doc_b1) and granted doc (doc_a2)
    res = c.get("/search")
    assert res.status_code == 200
    results = res.json()
    assert len(results) == 2
    returned_ids = {d["id"] for d in results}
    assert str(doc_b1.id) in returned_ids
    assert str(doc_a2.id) in returned_ids
    assert str(doc_a1.id) not in returned_ids  # Secret doc never leaked

    # 4. Stranger Charlie (no grants) searches -> Sees 0 docs, no counts or names leaked
    app.dependency_overrides[get_current_user] = lambda: viewer_c
    res = c.get("/search")
    assert res.status_code == 200
    assert len(res.json()) == 0

    res = c.get("/search?name=Phoenix")
    assert res.status_code == 200
    assert len(res.json()) == 0

    app.dependency_overrides.clear()


def test_search_filters_and_audit():
    now = datetime.now(timezone.utc)
    user = User(id=uuid.uuid4(), email="alice@tv.local", name="Alice", pw_hash="h", role="owner", is_active=True, token_version=1)

    t1 = now - timedelta(days=10)
    t2 = now - timedelta(days=2)
    t3 = now

    doc1 = Document(id=uuid.uuid4(), owner_id=user.id, name="Tax Return 2025.pdf", category="Tax", created_at=t1, deleted_at=None)
    doc2 = Document(id=uuid.uuid4(), owner_id=user.id, name="Tax Estimate 2026.pdf", category="Tax", created_at=t2, deleted_at=None)
    doc3 = Document(id=uuid.uuid4(), owner_id=user.id, name="Corporate Meeting.docx", category="Legal", created_at=t3, deleted_at=None)

    db = SearchMockDB(users=[user], docs=[doc1, doc2, doc3])
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: user

    c = TestClient(app)

    # 1. ILIKE name filter
    res = c.get("/search?name=tax")
    assert res.status_code == 200
    assert len(res.json()) == 2

    res = c.get("/search?name=RETURN")
    assert res.status_code == 200
    assert len(res.json()) == 1
    assert res.json()[0]["id"] == str(doc1.id)

    # 2. ILIKE category filter
    res = c.get("/search?category=legal")
    assert res.status_code == 200
    assert len(res.json()) == 1
    assert res.json()[0]["id"] == str(doc3.id)

    # 3. Owner filter
    res = c.get(f"/search?owner={user.email}")
    assert res.status_code == 200
    assert len(res.json()) == 3

    res = c.get("/search?owner=nonexistent@tv.local")
    assert res.status_code == 200
    assert len(res.json()) == 0

    # 4. Date range filter
    from_str = (now - timedelta(days=5)).strftime("%Y-%m-%d")
    to_str = (now + timedelta(days=1)).strftime("%Y-%m-%d")
    res = c.get(f"/search?from_date={from_str}&to_date={to_str}")
    assert res.status_code == 200
    # Should match doc2 and doc3, but exclude doc1 (10 days old)
    assert len(res.json()) == 2
    matched_ids = {d["id"] for d in res.json()}
    assert str(doc2.id) in matched_ids
    assert str(doc3.id) in matched_ids

    # 5. Also works on /api/search and /documents/search
    res_api = c.get("/api/search?category=Tax")
    assert res_api.status_code == 200
    assert len(res_api.json()) == 2

    res_docs = c.get("/documents/search?category=Tax")
    assert res_docs.status_code == 200
    assert len(res_docs.json()) == 2

    # 6. Audit trail verified
    audit_search_events = [e for e in db.audit_events if e.action == "doc_search"]
    assert len(audit_search_events) > 0
    last_evt = audit_search_events[-1]
    assert last_evt.outcome == "allowed"
    assert last_evt.actor_id == user.id

    app.dependency_overrides.clear()
