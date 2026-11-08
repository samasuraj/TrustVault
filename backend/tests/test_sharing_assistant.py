import json
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db import get_db
from app.deps import get_current_user
from app.models import Document, DocVersion, Grant, User, AuditEvent
from app.sharing_assistant import _SUGGESTIONS

class SharingAssistantMockDB:
    def __init__(self, users=None, docs=None, versions=None, grants=None):
        self.users = {u.id: u for u in (users or [])}
        self.users_by_email = {u.email.lower(): u for u in (users or [])}
        self.docs = {d.id: d for d in (docs or [])}
        self.versions = {v.id: v for v in (versions or [])}
        self.grants = {g.id: g for g in (grants or [])}
        self.audit_events = []

    def add(self, obj):
        if isinstance(obj, Grant):
            self.grants[obj.id] = obj
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
                        if "users.email" in s and hasattr(arg, "right"):
                            val = arg.right.value
                            if val:
                                return self.users_by_email.get(str(val).lower())
                        if "users.id" in s and hasattr(arg, "right"):
                            val = arg.right.value
                            if val in self.users:
                                return self.users[val]
                    return list(self.users.values())[0] if self.users else None

                def all_users():
                    matched = []
                    for u in self.users.values():
                        excluded = False
                        for arg in args:
                            s = str(arg)
                            if "users.id !=" in s and hasattr(arg, "right") and u.id == arg.right.value:
                                excluded = True
                            if "users.is_active = true" in s.lower() and not u.is_active:
                                excluded = True
                        if not excluded:
                            matched.append(u)
                    return matched

                fq.first.side_effect = first_user
                fq.all.side_effect = all_users
                return fq

            q.filter.side_effect = filter_user
            q.all.side_effect = lambda: list(self.users.values())
            return q

        elif model == Document:
            def filter_doc(*args, **kwargs):
                fq = MagicMock()
                def first_doc():
                    for arg in args:
                        if hasattr(arg, "right") and arg.right.value in self.docs:
                            return self.docs[arg.right.value]
                    return list(self.docs.values())[0] if self.docs else None
                fq.first.side_effect = first_doc
                fq.all.side_effect = lambda: list(self.docs.values())
                return fq
            q.filter.side_effect = filter_doc
            return q

        elif model == Grant:
            def filter_grant(*args, **kwargs):
                fq = MagicMock()
                now = datetime.now(timezone.utc)

                def all_grants():
                    matched = []
                    for g in self.grants.values():
                        excluded = False
                        for arg in args:
                            s = str(arg)
                            if "grants.doc_id =" in s and hasattr(arg, "right") and g.doc_id != arg.right.value:
                                excluded = True
                            if "grants.user_id =" in s and hasattr(arg, "right") and g.user_id != arg.right.value:
                                excluded = True
                            if "grants.revoked_at IS NULL" in s and g.revoked_at is not None:
                                excluded = True
                        if not excluded:
                            matched.append(g)
                    return matched

                def first_grant():
                    matches = all_grants()
                    return matches[0] if matches else None

                fq.all.side_effect = all_grants
                fq.first.side_effect = first_grant
                return fq

            q.filter.side_effect = filter_grant
            q.all.side_effect = lambda: list(self.grants.values())
            return q

        elif model == AuditEvent:
            oq = MagicMock()
            oq.with_for_update.return_value = oq
            oq.first.side_effect = lambda: self.audit_events[-1] if self.audit_events else None
            q.order_by.return_value = oq
            q.filter.return_value.order_by.return_value.all.side_effect = lambda: [
                e for e in self.audit_events if e.action == "suggest_access"
            ]

        return q


def test_suggest_endpoint_changes_no_grants():
    """
    Test requirement: suggest endpoint changes no grants.
    """
    _SUGGESTIONS.clear()
    now = datetime.now(timezone.utc)
    owner = User(id=uuid.uuid4(), email="owner@tv.local", name="Owner", pw_hash="h", role="owner", is_active=True, token_version=1)
    viewer1 = User(id=uuid.uuid4(), email="viewer1@tv.local", name="Viewer 1", pw_hash="h", role="viewer", is_active=True, token_version=1)
    viewer2 = User(id=uuid.uuid4(), email="viewer2@tv.local", name="Viewer 2", pw_hash="h", role="viewer", is_active=True, token_version=1)

    doc = Document(id=uuid.uuid4(), owner_id=owner.id, name="Q3 Report.pdf", category="Finance", created_at=now, deleted_at=None)

    db = SharingAssistantMockDB(users=[owner, viewer1, viewer2], docs=[doc], grants=[])
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: owner

    c = TestClient(app)

    grants_count_before = len(db.grants)

    # Owner calls suggest-access
    res = c.post(f"/documents/{doc.id}/suggest-access")
    assert res.status_code == 200
    data = res.json()

    assert "sid" in data
    assert "suggestions" in data
    assert len(data["suggestions"]) > 0

    # Non-negotiable test requirement: suggest endpoint changes NO grants
    grants_count_after = len(db.grants)
    assert grants_count_after == grants_count_before
    assert len(db.grants) == 0

    app.dependency_overrides.clear()


def test_suggest_and_confirm_by_non_owner_fails():
    """
    Test requirement: confirm by non-owner fails (and suggest by non-owner fails).
    Security Rule 2: Deny by default (404, existence not leaked).
    """
    _SUGGESTIONS.clear()
    now = datetime.now(timezone.utc)
    owner = User(id=uuid.uuid4(), email="owner@tv.local", name="Owner", pw_hash="h", role="owner", is_active=True, token_version=1)
    stranger = User(id=uuid.uuid4(), email="stranger@tv.local", name="Stranger", pw_hash="h", role="viewer", is_active=True, token_version=1)
    admin = User(id=uuid.uuid4(), email="admin@tv.local", name="Admin", pw_hash="h", role="admin", is_active=True, token_version=1)

    doc = Document(id=uuid.uuid4(), owner_id=owner.id, name="Secret NDA.pdf", category="Legal", created_at=now, deleted_at=None)

    db = SharingAssistantMockDB(users=[owner, stranger, admin], docs=[doc])
    app.dependency_overrides[get_db] = lambda: db

    c = TestClient(app)

    # 1. Owner generates suggestions
    app.dependency_overrides[get_current_user] = lambda: owner
    res = c.post(f"/documents/{doc.id}/suggest-access")
    assert res.status_code == 200
    sid = res.json()["sid"]

    # 2. Non-owner stranger attempts to suggest -> 404
    app.dependency_overrides[get_current_user] = lambda: stranger
    res_stranger_suggest = c.post(f"/documents/{doc.id}/suggest-access")
    assert res_stranger_suggest.status_code == 404

    # 3. Non-owner stranger attempts to confirm -> 404
    payload = {"grants": [{"user_email": "stranger@tv.local", "perm": "read"}]}
    res_stranger_confirm = c.post(f"/documents/{doc.id}/suggestions/{sid}/confirm", json=payload)
    assert res_stranger_confirm.status_code == 404
    assert len(db.grants) == 0  # No grants created

    # 4. Admin (without doc ownership or explicit grant) cannot confirm -> 404
    app.dependency_overrides[get_current_user] = lambda: admin
    res_admin_confirm = c.post(f"/documents/{doc.id}/suggestions/{sid}/confirm", json=payload)
    assert res_admin_confirm.status_code == 404
    assert len(db.grants) == 0

    # 5. Non-existent suggestion id with owner -> 404
    app.dependency_overrides[get_current_user] = lambda: owner
    fake_sid = uuid.uuid4()
    res_fake = c.post(f"/documents/{doc.id}/suggestions/{fake_sid}/confirm", json=payload)
    assert res_fake.status_code == 404

    # 6. Verify denied audit events written
    denied_events = [e for e in db.audit_events if e.outcome == "denied"]
    assert len(denied_events) > 0

    app.dependency_overrides.clear()


def test_deterministic_heuristics():
    """
    Tests deterministic heuristics:
    - User previously granted same-category docs
    - User previously granted similar-category docs
    - User collaborated with owner on other docs
    - Exclusion of owner and already-granted users
    """
    _SUGGESTIONS.clear()
    now = datetime.now(timezone.utc)
    owner = User(id=uuid.uuid4(), email="owner@tv.local", name="Owner", pw_hash="h", role="owner", is_active=True, token_version=1)

    u_same_cat = User(id=uuid.uuid4(), email="same_cat@tv.local", name="Same Category Collab", pw_hash="h", role="viewer", is_active=True, token_version=1)
    u_sim_cat = User(id=uuid.uuid4(), email="sim_cat@tv.local", name="Similar Category Collab", pw_hash="h", role="viewer", is_active=True, token_version=1)
    u_owner_collab = User(id=uuid.uuid4(), email="owner_collab@tv.local", name="Owner Collab", pw_hash="h", role="viewer", is_active=True, token_version=1)
    u_already_active = User(id=uuid.uuid4(), email="already_active@tv.local", name="Already Active", pw_hash="h", role="viewer", is_active=True, token_version=1)
    u_fresh = User(id=uuid.uuid4(), email="fresh@tv.local", name="Fresh Viewer", pw_hash="h", role="viewer", is_active=True, token_version=1)

    # Target document to share: category "Legal"
    doc_target = Document(id=uuid.uuid4(), owner_id=owner.id, name="NDA 2026.pdf", category="Legal", created_at=now, deleted_at=None)

    # Other documents
    doc_legal_other = Document(id=uuid.uuid4(), owner_id=owner.id, name="Past Contract.pdf", category="Legal", created_at=now, deleted_at=None)
    doc_legal_sim = Document(id=uuid.uuid4(), owner_id=owner.id, name="Compliance Legal.pdf", category="Legal Compliance", created_at=now, deleted_at=None)
    doc_eng = Document(id=uuid.uuid4(), owner_id=owner.id, name="Architecture.pdf", category="Engineering", created_at=now, deleted_at=None)

    # Grants history:
    # 1. u_same_cat was granted doc_legal_other (same category)
    g1 = Grant(id=uuid.uuid4(), doc_id=doc_legal_other.id, user_id=u_same_cat.id, perm="edit", granted_by=owner.id, granted_at=now, revoked_at=None, expires_at=None)
    # 2. u_sim_cat was granted doc_legal_sim (similar category)
    g2 = Grant(id=uuid.uuid4(), doc_id=doc_legal_sim.id, user_id=u_sim_cat.id, perm="read", granted_by=owner.id, granted_at=now, revoked_at=None, expires_at=None)
    # 3. u_owner_collab was granted doc_eng
    g3 = Grant(id=uuid.uuid4(), doc_id=doc_eng.id, user_id=u_owner_collab.id, perm="read", granted_by=owner.id, granted_at=now, revoked_at=None, expires_at=None)
    # 4. u_already_active ALREADY has active grant on doc_target
    g4 = Grant(id=uuid.uuid4(), doc_id=doc_target.id, user_id=u_already_active.id, perm="read", granted_by=owner.id, granted_at=now, revoked_at=None, expires_at=None)

    db = SharingAssistantMockDB(
        users=[owner, u_same_cat, u_sim_cat, u_owner_collab, u_already_active, u_fresh],
        docs=[doc_target, doc_legal_other, doc_legal_sim, doc_eng],
        grants=[g1, g2, g3, g4],
    )
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: owner

    c = TestClient(app)
    res = c.post(f"/documents/{doc_target.id}/suggest-access")
    assert res.status_code == 200
    suggestions = res.json()["suggestions"]

    emails = [s["email"] for s in suggestions]
    # Owner and already-granted user must NOT be suggested
    assert owner.email not in emails
    assert u_already_active.email not in emails

    # User with same category history ranks first
    assert emails[0] == u_same_cat.email
    assert "Legal" in suggestions[0]["reason"]

    # User with similar category has reason mentioning similar category
    sim_item = next(s for s in suggestions if s["email"] == u_sim_cat.email)
    assert "similar" in sim_item["reason"].lower() or "Legal" in sim_item["reason"]

    # User with owner collaboration has reason mentioning collaboration
    owner_collab_item = next(s for s in suggestions if s["email"] == u_owner_collab.email)
    assert "collaborat" in owner_collab_item["reason"].lower() or "other" in owner_collab_item["reason"].lower()

    app.dependency_overrides.clear()


def test_optional_llm_call_without_file_contents(monkeypatch):
    """
    Test requirement: optional LLM call if ANTHROPIC_API_KEY is set that sees
    only doc name/category/description, never file contents.
    """
    _SUGGESTIONS.clear()
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-999")

    now = datetime.now(timezone.utc)
    owner = User(id=uuid.uuid4(), email="owner@tv.local", name="Owner", pw_hash="h", role="owner", is_active=True, token_version=1)
    viewer = User(id=uuid.uuid4(), email="analyst@tv.local", name="Financial Analyst", pw_hash="h", role="viewer", is_active=True, token_version=1)

    doc = Document(
        id=uuid.uuid4(), owner_id=owner.id, name="FY26 Quarterly Forecast.xlsx",
        category="Finance", description="Confidential earnings model",
        created_at=now, deleted_at=None
    )

    db = SharingAssistantMockDB(users=[owner, viewer], docs=[doc])
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: owner

    mock_llm_response = MagicMock()
    mock_llm_response.status_code = 200
    mock_llm_response.json.return_value = {
        "content": [
            {
                "text": json.dumps([
                    {
                        "email": "analyst@tv.local",
                        "perm": "read",
                        "reason": "Matches financial analysis role for quarterly earnings forecasting."
                    }
                ])
            }
        ]
    }

    recorded_payloads = []

    def mock_post(url, headers=None, json=None, timeout=None):
        recorded_payloads.append((url, headers, json))
        return mock_llm_response

    with patch("httpx.post", side_effect=mock_post):
        c = TestClient(app)
        res = c.post(f"/documents/{doc.id}/suggest-access")
        assert res.status_code == 200
        data = res.json()
        assert len(data["suggestions"]) == 1
        s = data["suggestions"][0]
        assert s["email"] == "analyst@tv.local"
        assert "[AI]" in s["reason"]

    # Non-negotiable security assertion: Anthropic call sees ONLY name/category/description, NEVER file contents
    assert len(recorded_payloads) == 1
    call_url, call_headers, call_json = recorded_payloads[0]
    prompt_text = call_json["messages"][0]["content"]

    assert doc.name in prompt_text
    assert doc.category in prompt_text
    assert doc.description in prompt_text
    # Ensure no file contents or version data passed
    assert "storage_key" not in prompt_text
    assert "decrypted" not in prompt_text
    assert "sha256" not in prompt_text

    app.dependency_overrides.clear()


def test_confirm_decisions_accepted_modified_rejected_and_audit():
    """
    Test requirement:
    - confirm requires owner to explicitly pick users and perms
    - audit both the suggestion (with what was suggested) and owner's decision (accepted/modified/rejected)
    """
    _SUGGESTIONS.clear()
    now = datetime.now(timezone.utc)
    owner = User(id=uuid.uuid4(), email="owner@tv.local", name="Owner", pw_hash="h", role="owner", is_active=True, token_version=1)
    viewer1 = User(id=uuid.uuid4(), email="v1@tv.local", name="V1", pw_hash="h", role="viewer", is_active=True, token_version=1)
    viewer2 = User(id=uuid.uuid4(), email="v2@tv.local", name="V2", pw_hash="h", role="viewer", is_active=True, token_version=1)

    doc = Document(id=uuid.uuid4(), owner_id=owner.id, name="Roadmap.pdf", category="Product", created_at=now, deleted_at=None)

    db = SharingAssistantMockDB(users=[owner, viewer1, viewer2], docs=[doc])
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: owner

    c = TestClient(app)

    # --- Scenario 1: Rejection ---
    res_s1 = c.post(f"/documents/{doc.id}/suggest-access")
    sid1 = res_s1.json()["sid"]
    res_confirm_reject = c.post(
        f"/documents/{doc.id}/suggestions/{sid1}/confirm",
        json={"decision": "rejected"}
    )
    assert res_confirm_reject.status_code == 200
    assert res_confirm_reject.json()["decision"] == "rejected"
    assert len(db.grants) == 0  # No grants created on reject

    # --- Scenario 2: Modification (picked subset or changed permission) ---
    res_s2 = c.post(f"/documents/{doc.id}/suggest-access")
    sid2 = res_s2.json()["sid"]
    res_confirm_modify = c.post(
        f"/documents/{doc.id}/suggestions/{sid2}/confirm",
        json={"grants": [{"user_email": "v1@tv.local", "perm": "edit"}]}
    )
    assert res_confirm_modify.status_code == 200
    assert res_confirm_modify.json()["decision"] == "modified"
    assert len(db.grants) == 1
    created_g = list(db.grants.values())[0]
    assert created_g.user_id == viewer1.id
    assert created_g.perm == "edit"

    # --- Scenario 3: Acceptance (owner picks exact suggestions) ---
    res_s3 = c.post(f"/documents/{doc.id}/suggest-access")
    sid3 = res_s3.json()["sid"]
    suggestions = res_s3.json()["suggestions"]
    exact_picks = [{"user_email": s["email"], "perm": s["perm"]} for s in suggestions]
    res_confirm_accept = c.post(
        f"/documents/{doc.id}/suggestions/{sid3}/confirm",
        json={"grants": exact_picks}
    )
    assert res_confirm_accept.status_code == 200
    assert res_confirm_accept.json()["decision"] == "accepted"

    # --- Audit Trail Verification ---
    # 1. suggest_access audit events
    suggest_events = [e for e in db.audit_events if e.action == "suggest_access"]
    assert len(suggest_events) >= 3
    for se in suggest_events:
        assert se.outcome == "allowed"
        assert se.actor_id == owner.id
        assert "sid" in se.detail
        assert "suggestions" in se.detail

    # 2. suggest_confirm audit events
    confirm_events = [e for e in db.audit_events if e.action == "suggest_confirm"]
    assert len(confirm_events) == 3
    decisions_logged = [ce.detail["decision"] for ce in confirm_events]
    assert "rejected" in decisions_logged
    assert "modified" in decisions_logged
    assert "accepted" in decisions_logged

    app.dependency_overrides.clear()
