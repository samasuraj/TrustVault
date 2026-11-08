from datetime import datetime, timezone
from uuid import UUID
from fastapi import HTTPException, status, Depends, Request
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import Document, Grant, AuditEvent, User
from app.deps import get_current_user, get_client_ip
from app.audit import log_event, record_audit, verify_chain, _hmac_hash

VALID_ACTIONS = {"read", "download", "edit", "delete", "share", "view_meta", "restore"}


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
    # Positional-or-keyword dispatch
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

    if not user or not getattr(user, "is_active", True):
        actor_id = getattr(user, "id", None) if user else None
        doc = db.query(Document).filter(Document.id == doc_id).first() if (db and doc_id) else None
        log_event(
            db,
            action=action,
            outcome="denied",
            actor_id=actor_id,
            doc_id=doc.id if doc else None,
            ip=ip,
            detail={"reason": "unauthenticated_or_disabled", **({"requested_doc_id": str(doc_id)} if not doc and doc_id else {})},
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    doc = db.query(Document).filter(Document.id == doc_id).first()

    if not doc:
        log_event(db, action=action, outcome="denied", actor_id=user.id, doc_id=None, ip=ip, detail={"reason": "not_found", "requested_doc_id": str(doc_id)})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    if doc.deleted_at is not None:
        if action == "restore" and doc.owner_id == user.id:
            log_event(db, action=action, outcome="allowed", actor_id=user.id, doc_id=doc.id, ip=ip)
            return doc
        log_event(db, action=action, outcome="denied", actor_id=user.id, doc_id=doc.id, ip=ip, detail={"reason": "doc_deleted"})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    if doc.owner_id == user.id:
        log_event(db, action=action, outcome="allowed", actor_id=user.id, doc_id=doc.id, ip=ip)
        return doc

    if action in ("delete", "share", "restore"):
        log_event(db, action=action, outcome="denied", actor_id=user.id, doc_id=doc.id, ip=ip, detail={"reason": "owner_only_action"})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

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
        past = (
            db.query(Grant)
            .filter(Grant.doc_id == doc.id, Grant.user_id == user.id)
            .order_by(Grant.granted_at.desc())
            .first()
        )
        reason = "no_active_grant"
        if past:
            if past.revoked_at is not None:
                reason = "grant_revoked"
            elif past.expires_at is not None and past.expires_at <= now:
                reason = "grant_expired"
        log_event(db, action=action, outcome="denied", actor_id=user.id, doc_id=doc.id, ip=ip, detail={"reason": reason})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    if grant.perm == "read" and action in ("read", "download", "view_meta"):
        log_event(db, action=action, outcome="allowed", actor_id=user.id, doc_id=doc.id, ip=ip)
        return doc

    if grant.perm == "edit" and action in ("read", "download", "view_meta", "edit"):
        log_event(db, action=action, outcome="allowed", actor_id=user.id, doc_id=doc.id, ip=ip)
        return doc

    log_event(db, action=action, outcome="denied", actor_id=user.id, doc_id=doc.id, ip=ip, detail={"reason": "insufficient_perm", "perm": grant.perm})
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
