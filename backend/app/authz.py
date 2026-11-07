import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.models import Document, Grant, AuditEvent, User

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

def authorize(user: User | None, doc_id: UUID, action: str, db: Session, ip: str | None = None) -> Document:
    doc = (
        db.query(Document)
        .filter(Document.id == doc_id, Document.deleted_at.is_(None))
        .first()
    )

    if not user:
        record_audit(db, action=action, outcome="denied", doc_id=doc_id, ip=ip, detail={"reason": "no_user"})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    if not doc:
        record_audit(db, action=action, outcome="denied", actor_id=user.id, doc_id=doc_id, ip=ip, detail={"reason": "not_found"})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    if user.role == "admin" or doc.owner_id == user.id:
        record_audit(db, action=action, outcome="allowed", actor_id=user.id, doc_id=doc.id, ip=ip)
        return doc

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
        record_audit(db, action=action, outcome="denied", actor_id=user.id, doc_id=doc.id, ip=ip, detail={"reason": "no_grant"})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    if action == "edit" and grant.perm != "edit":
        record_audit(db, action=action, outcome="denied", actor_id=user.id, doc_id=doc.id, ip=ip, detail={"reason": "insufficient_perm"})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    record_audit(db, action=action, outcome="allowed", actor_id=user.id, doc_id=doc.id, ip=ip)
    return doc
