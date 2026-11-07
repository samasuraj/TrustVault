import hashlib
import hmac
import json
from datetime import datetime, timezone
from uuid import UUID
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.config import cfg
from app.models import AuditEvent

_AUDIT_LOCK_KEY = 7_777_777_777


def canonical_json(val: dict) -> str:
    return json.dumps(val, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(secret: str, prev_hash: str | None, payload: dict) -> str:
    message = f"{prev_hash or ''}{canonical_json(payload)}"
    return hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _hmac_hash(prev_hash: str | None, payload: dict) -> str:
    return compute_hash(cfg.audit_hmac_key, prev_hash, payload)


def format_ts(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def log_event(
    db: Session,
    action: str,
    outcome: str,
    actor_id: UUID | None = None,
    doc_id: UUID | None = None,
    target_user_id: UUID | None = None,
    ip: str | None = None,
    detail: dict | None = None,
) -> AuditEvent:
    """Single entry-point for all audit writes. Uses advisory lock + transaction
    so the hash chain is consistent under concurrent inserts."""
    if detail is None:
        detail = {}

    has_lock = False
    if hasattr(db, "execute"):
        try:
            db.execute(text(f"SELECT pg_advisory_lock({_AUDIT_LOCK_KEY})"))
            has_lock = True
        except Exception:
            pass

    try:
        q = db.query(AuditEvent).order_by(AuditEvent.id.desc())
        if hasattr(q, "with_for_update"):
            try:
                q = q.with_for_update()
            except Exception:
                pass
        last = q.first()
        prev = last.hash if last else None

        now = datetime.now(timezone.utc)
        payload = {
            "ts": format_ts(now),
            "actor_id": str(actor_id) if actor_id else None,
            "action": action,
            "doc_id": str(doc_id) if doc_id else None,
            "target_user_id": str(target_user_id) if target_user_id else None,
            "outcome": outcome,
            "ip": ip,
            "detail": detail,
        }
        h = compute_hash(cfg.audit_hmac_key, prev, payload)

        evt = AuditEvent(
            ts=now,
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
    finally:
        if has_lock:
            try:
                db.execute(text(f"SELECT pg_advisory_unlock({_AUDIT_LOCK_KEY})"))
            except Exception:
                pass


# Backward-compatible alias
record_audit = log_event


def verify_chain(db: Session) -> dict:
    """Walk the entire audit chain, return first broken link or ok."""
    events = (
        db.query(AuditEvent)
        .order_by(AuditEvent.id.asc())
        .all()
    )
    prev_hash: str | None = None
    for evt in events:
        payload = {
            "ts": format_ts(evt.ts) if evt.ts else None,
            "actor_id": str(evt.actor_id) if evt.actor_id else None,
            "action": evt.action,
            "doc_id": str(evt.doc_id) if evt.doc_id else None,
            "target_user_id": str(evt.target_user_id) if evt.target_user_id else None,
            "outcome": evt.outcome,
            "ip": evt.ip,
            "detail": evt.detail if evt.detail is not None else {},
        }
        expected_prev = prev_hash
        expected_hash = compute_hash(cfg.audit_hmac_key, expected_prev, payload)

        if evt.prev_hash != expected_prev:
            return {
                "ok": False,
                "broken_at_id": evt.id,
                "reason": "prev_hash_mismatch",
                "expected_prev": expected_prev,
                "stored_prev": evt.prev_hash,
            }
        if evt.hash != expected_hash:
            return {
                "ok": False,
                "broken_at_id": evt.id,
                "reason": "hash_mismatch",
                "expected_hash": expected_hash,
                "stored_hash": evt.hash,
            }
        prev_hash = evt.hash

    return {"ok": True, "total_events": len(events)}
