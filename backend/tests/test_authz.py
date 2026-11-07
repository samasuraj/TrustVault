import uuid
from unittest.mock import MagicMock
import pytest
from fastapi import HTTPException
from app.authz import authorize, record_audit, _hmac_hash

def test_compute_hash_deterministic():
    p1 = {"a": 1, "b": "test"}
    p2 = {"b": "test", "a": 1}
    assert _hmac_hash("prev123", p1) == _hmac_hash("prev123", p2)
    assert _hmac_hash("prev123", p1) != _hmac_hash("prev456", p1)

def test_record_audit():
    db = MagicMock()
    # Satisfy advisory lock execute calls
    db.execute.return_value = None
    # For the last-event query (with_for_update)
    db.query.return_value.order_by.return_value.with_for_update.return_value.first.return_value = None

    evt = record_audit(
        db=db,
        action="read",
        outcome="allowed",
        actor_id=uuid.uuid4(),
        doc_id=uuid.uuid4(),
        ip="127.0.0.1",
    )
    assert evt.prev_hash is None
    assert evt.hash is not None
    assert evt.outcome == "allowed"
    db.add.assert_called_once()
    db.commit.assert_called_once()


def test_authorize_anonymous_raises_404():
    db = MagicMock()
    doc_id = uuid.uuid4()
    with pytest.raises(HTTPException) as exc:
        authorize(user=None, doc_id=doc_id, action="read", db=db)
    assert exc.value.status_code == 404

def test_authorize_missing_doc_raises_404():
    db = MagicMock()
    user = MagicMock(id=uuid.uuid4(), role="viewer")
    doc_id = uuid.uuid4()
    db.query().filter().first.return_value = None

    with pytest.raises(HTTPException) as exc:
        authorize(user=user, doc_id=doc_id, action="read", db=db)
    assert exc.value.status_code == 404

def test_authorize_owner_allowed():
    db = MagicMock()
    user_id = uuid.uuid4()
    user = MagicMock(id=user_id, role="viewer", is_active=True)
    doc_id = uuid.uuid4()
    doc = MagicMock(id=doc_id, owner_id=user_id, deleted_at=None)

    db.query().filter().first.return_value = doc
    res = authorize(user=user, doc_id=doc_id, action="edit", db=db)
    assert res == doc

def test_authorize_admin_without_grant_raises_404():
    db = MagicMock()
    user = MagicMock(id=uuid.uuid4(), role="admin", is_active=True)
    doc_id = uuid.uuid4()
    doc = MagicMock(id=doc_id, owner_id=uuid.uuid4(), deleted_at=None)

    query_mock = db.query.return_value
    query_mock.filter.return_value.first.side_effect = [doc, None]

    with pytest.raises(HTTPException) as exc:
        authorize(user=user, doc_id=doc_id, action="read", db=db)
    assert exc.value.status_code == 404

def test_authorize_admin_with_grant_allowed():
    db = MagicMock()
    user = MagicMock(id=uuid.uuid4(), role="admin", is_active=True)
    doc_id = uuid.uuid4()
    doc = MagicMock(id=doc_id, owner_id=uuid.uuid4(), deleted_at=None)
    grant = MagicMock(perm="read")

    query_mock = db.query.return_value
    query_mock.filter.return_value.first.side_effect = [doc, grant]

    res = authorize(user=user, doc_id=doc_id, action="read", db=db)
    assert res == doc

def test_authorize_disabled_user_raises_404():
    db = MagicMock()
    user = MagicMock(id=uuid.uuid4(), role="owner", is_active=False)
    doc_id = uuid.uuid4()

    with pytest.raises(HTTPException) as exc:
        authorize(user=user, doc_id=doc_id, action="read", db=db)
    assert exc.value.status_code == 404

def test_authorize_unauthorized_user_raises_404_not_403():
    db = MagicMock()
    user = MagicMock(id=uuid.uuid4(), role="viewer", is_active=True)
    doc_id = uuid.uuid4()
    doc = MagicMock(id=doc_id, owner_id=uuid.uuid4(), deleted_at=None)

    # First query returns doc, second query for grant returns None
    query_mock = db.query.return_value
    query_mock.filter.return_value.first.side_effect = [doc, None]

    with pytest.raises(HTTPException) as exc:
        authorize(user=user, doc_id=doc_id, action="read", db=db)
    # Must be 404 per Rule 2 (never leak doc existence via 403)
    assert exc.value.status_code == 404

def test_authorize_read_grant_cannot_edit():
    db = MagicMock()
    user = MagicMock(id=uuid.uuid4(), role="viewer", is_active=True)
    doc_id = uuid.uuid4()
    doc = MagicMock(id=doc_id, owner_id=uuid.uuid4(), deleted_at=None)
    grant = MagicMock(perm="read")

    query_mock = db.query.return_value
    query_mock.filter.return_value.first.side_effect = [doc, grant]

    with pytest.raises(HTTPException) as exc:
        authorize(user=user, doc_id=doc_id, action="edit", db=db)
    assert exc.value.status_code == 404
