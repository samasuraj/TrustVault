import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID
from fastapi import HTTPException, status, Depends, Request
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import Document, Grant, AuditEvent, User
from app.deps import get_current_user, get_client_ip

VALID_ACTIONS = {"read", "download", "edit", "delete", "share", "view_meta", "restore"}

def _compute_hash(prev_hash: str | None, payload: dict) -> str:
    raw = f"{prev_hash or ''}:{json.dumps(payload, sort_keys=True)}"
    return hashlib.sha256(raw.encode()).hexdigest()

def record_audit(
    db: Session,
    action: str,
    outcome: str,
    actor_id: UUID | None = None,
    doc_id: UUID | None = None,
    target_user_id: UUID | None = None,
    ip: str | None = None,
    detail: dict | None = None,
) -> AuditEvent:
    if detail is None:
        detail = {}

    last = (
        db.query(AuditEvent)
        .order_by(AuditEvent.id.desc())
        .first()
    )
    prev = last.hash if last else None

    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "actor_id": str(actor_id) if actor_id else None,
        "action": action,
        "doc_id": str(doc_id) if doc_id else None,
        "target_user_id": str(target_user_id) if target_user_id else None,
        "outcome": outcome,
        "ip": ip,
        "detail": detail,
    }
    h = _compute_hash(prev, payload)

    evt = AuditEvent(
        actor_id=actor_id,
        action=action,
        doc_id=doc_id,
        target_user_id=target_user_id,
        outcome=outcome,
        ip=ip,
        detail=detail,
        prev_hash=prev,
        hash=h,
    )
    db.add(evt)
    db.commit()
    db.refresh(evt)
    return evt

def authorize(
    db_or_user=None,
    user_or_doc_id=None,
    doc_id_or_action=None,
    action_or_db=None,
    ip: str | None = None,
    db: Session | None = None,
    user: User | None = None,
    doc_id: UUID | None = None,
    action: str | None = None,
) -> Document:
    # If called with keyword arguments
    if db is not None:
        pass
    elif hasattr(db_or_user, "query"):
        db = db_or_user
        user = user_or_doc_id
        doc_id = doc_id_or_action
        action = action_or_db
    else:
        user = db_or_user
        doc_id = user_or_doc_id
        action = doc_id_or_action
        db = action_or_db

    if action not in VALID_ACTIONS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid action: {action}")

    # Deny by default if user is missing or disabled
    if not user or not getattr(user, "is_active", True):
        actor_id = getattr(user, "id", None) if user else None
        record_audit(db, action=action, outcome="denied", actor_id=actor_id, doc_id=doc_id, ip=ip, detail={"reason": "unauthenticated_or_disabled"})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    # Always query DB fresh, no caching
    doc = (
        db.query(Document)
        .filter(Document.id == doc_id)
        .first()
    )

    if not doc:
        record_audit(db, action=action, outcome="denied", actor_id=user.id, doc_id=doc_id, ip=ip, detail={"reason": "not_found"})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    # Soft-deleted docs are inaccessible except to owner for restore
    if doc.deleted_at is not None:
        if action == "restore" and doc.owner_id == user.id:
            record_audit(db, action=action, outcome="allowed", actor_id=user.id, doc_id=doc.id, ip=ip)
            return doc
        record_audit(db, action=action, outcome="denied", actor_id=user.id, doc_id=doc.id, ip=ip, detail={"reason": "doc_deleted"})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    # Doc owner = all actions allowed
    if doc.owner_id == user.id:
        record_audit(db, action=action, outcome="allowed", actor_id=user.id, doc_id=doc.id, ip=ip)
        return doc

    # Only owner may share or delete
    if action in ("delete", "share", "restore"):
        record_audit(db, action=action, outcome="denied", actor_id=user.id, doc_id=doc.id, ip=ip, detail={"reason": "owner_only_action"})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    # Admin gets NO content access by default without explicit active grant
    now = datetime.now(timezone.utc)
    grant = (
        db.query(Grant)
        .filter(
            Grant.doc_id == doc.id,
            Grant.user_id == user.id,
            Grant.revoked_at.is_(None),
            (Grant.expires_at.is_(None) | (Grant.expires_at > now)),
        )
        .first()
    )

    if not grant:
        record_audit(db, action=action, outcome="denied", actor_id=user.id, doc_id=doc.id, ip=ip, detail={"reason": "no_active_grant"})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    # Active grant checks
    if grant.perm == "read" and action in ("read", "download", "view_meta"):
        record_audit(db, action=action, outcome="allowed", actor_id=user.id, doc_id=doc.id, ip=ip)
        return doc

    if grant.perm == "edit" and action in ("read", "download", "view_meta", "edit"):
        record_audit(db, action=action, outcome="allowed", actor_id=user.id, doc_id=doc.id, ip=ip)
        return doc

    # Insufficient grant permission
    record_audit(db, action=action, outcome="denied", actor_id=user.id, doc_id=doc.id, ip=ip, detail={"reason": "insufficient_perm", "perm": grant.perm})
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

class RequireDocAccess:
    def __init__(self, action: str):
        self.action = action

    def __call__(
        self,
        doc_id: UUID,
        req: Request,
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user),
    ) -> Document:
        ip = get_client_ip(req)
        return authorize(db, user, doc_id, self.action, ip=ip)
