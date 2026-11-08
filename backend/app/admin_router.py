import csv
import io
from datetime import datetime, timedelta, timezone
from uuid import UUID
from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, and_, or_
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_client_ip, require_admin
from app.models import AuditEvent, User, Document, Grant
from app.authz import log_event, verify_chain

router = APIRouter(tags=["admin"])


# ── schemas ──────────────────────────────────────────────────────────────────

class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ts: datetime | None = None
    actor_id: UUID | None = None
    action: str
    doc_id: UUID | None = None
    target_user_id: UUID | None = None
    outcome: str
    ip: str | None = None
    detail: dict = {}
    prev_hash: str | None = None
    hash: str


class AlertItem(BaseModel):
    alert_type: str
    description: str
    actor_id: UUID | None = None
    doc_id: UUID | None = None
    ts: datetime
    detail: dict = {}


# ── helpers ───────────────────────────────────────────────────────────────────

def _base_audit_query(
    db: Session,
    actor_id: UUID | None,
    doc_id: UUID | None,
    action: str | None,
    outcome: str | None,
    since: datetime | None,
    until: datetime | None,
):
    q = db.query(AuditEvent)
    if actor_id:
        q = q.filter(AuditEvent.actor_id == actor_id)
    if doc_id:
        q = q.filter(AuditEvent.doc_id == doc_id)
    if action:
        q = q.filter(AuditEvent.action == action)
    if outcome:
        q = q.filter(AuditEvent.outcome == outcome)
    if since:
        q = q.filter(AuditEvent.ts >= since)
    if until:
        q = q.filter(AuditEvent.ts <= until)
    return q


def _detect_alerts(db: Session) -> list[AlertItem]:
    alerts: list[AlertItem] = []
    now = datetime.now(timezone.utc)
    window_10m = now - timedelta(minutes=10)
    window_1h  = now - timedelta(hours=1)
    window_8h  = now - timedelta(hours=8)  # "odd hours" = midnight-06:00 UTC block

    # 1. Many denials by one user in 10 min (threshold: 10)
    denial_rows = (
        db.query(AuditEvent.actor_id, func.count().label("n"))
        .filter(
            AuditEvent.outcome == "denied",
            AuditEvent.ts >= window_10m,
            AuditEvent.actor_id.isnot(None),
        )
        .group_by(AuditEvent.actor_id)
        .having(func.count() >= 5)
        .all()
    )
    for row in denial_rows:
        alerts.append(AlertItem(
            alert_type="many_denials",
            description=f"User had {row.n} denied attempts in the last 10 minutes",
            actor_id=row.actor_id,
            ts=now,
            detail={"denial_count": row.n, "window_minutes": 10},
        ))

    # 2. Downloads at odd hours (00:00–06:00 UTC) in the last 8 hours
    odd_rows = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action.in_(("download", "doc_download", "token_redeem")),
            AuditEvent.outcome == "allowed",
            AuditEvent.ts >= window_8h,
            func.extract("hour", AuditEvent.ts).between(0, 5),
        )
        .all()
    )
    for evt in odd_rows:
        alerts.append(AlertItem(
            alert_type="odd_hour_download",
            description="Document downloaded during off-hours (00:00–06:00 UTC)",
            actor_id=evt.actor_id,
            doc_id=evt.doc_id,
            ts=evt.ts,
            detail={"action": evt.action},
        ))

    # 3. Bulk downloads: >5 download events by same user in 1 hour
    bulk_rows = (
        db.query(AuditEvent.actor_id, func.count().label("n"))
        .filter(
            AuditEvent.action.in_(("download", "doc_download", "token_redeem")),
            AuditEvent.outcome == "allowed",
            AuditEvent.ts >= window_1h,
            AuditEvent.actor_id.isnot(None),
        )
        .group_by(AuditEvent.actor_id)
        .having(func.count() >= 5)
        .all()
    )
    for row in bulk_rows:
        alerts.append(AlertItem(
            alert_type="bulk_download",
            description=f"User downloaded {row.n} documents in the last hour",
            actor_id=row.actor_id,
            ts=now,
            detail={"download_count": row.n, "window_hours": 1},
        ))

    # 4. Grant then immediate download by a new user (grant + download within 60s)
    recent_grants = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action == "grant_create",
            AuditEvent.outcome == "allowed",
            AuditEvent.ts >= window_10m,
        )
        .all()
    )
    for g_evt in recent_grants:
        if not g_evt.target_user_id or not g_evt.doc_id:
            continue
        quick_dl = (
            db.query(AuditEvent)
            .filter(
                AuditEvent.actor_id == g_evt.target_user_id,
                AuditEvent.doc_id == g_evt.doc_id,
                AuditEvent.action.in_(("download", "doc_download", "token_redeem")),
                AuditEvent.outcome == "allowed",
                AuditEvent.ts >= g_evt.ts,
                AuditEvent.ts <= g_evt.ts + timedelta(seconds=60),
            )
            .first()
        )
        if quick_dl:
            alerts.append(AlertItem(
                alert_type="grant_then_immediate_download",
                description="User downloaded a document within 60s of being granted access",
                actor_id=g_evt.target_user_id,
                doc_id=g_evt.doc_id,
                ts=quick_dl.ts,
                detail={"grant_event_id": g_evt.id, "download_event_id": quick_dl.id},
            ))

    # 5. Access just before revocation (download within 120s before grant_revoke)
    recent_revokes = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action == "grant_revoke",
            AuditEvent.outcome == "allowed",
            AuditEvent.ts >= window_10m,
        )
        .all()
    )
    for r_evt in recent_revokes:
        if not r_evt.doc_id:
            continue
        pre_access = (
            db.query(AuditEvent)
            .filter(
                AuditEvent.doc_id == r_evt.doc_id,
                AuditEvent.action.in_(("download", "doc_download", "token_redeem")),
                AuditEvent.outcome == "allowed",
                AuditEvent.ts >= r_evt.ts - timedelta(seconds=120),
                AuditEvent.ts <= r_evt.ts,
            )
            .first()
        )
        if pre_access:
            alerts.append(AlertItem(
                alert_type="access_before_revocation",
                description="Document accessed within 2 minutes before access was revoked",
                actor_id=pre_access.actor_id,
                doc_id=r_evt.doc_id,
                ts=pre_access.ts,
                detail={"revoke_event_id": r_evt.id, "access_event_id": pre_access.id},
            ))

    return alerts


# ── routes ────────────────────────────────────────────────────────────────────

@router.get("/audit/verify")
def audit_verify(
    req: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    ip = get_client_ip(req)
    result = verify_chain(db)
    log_event(
        db,
        action="audit_verify",
        outcome="allowed",
        actor_id=admin.id,
        ip=ip,
        detail=result,
    )
    return result


@router.get("/audit", response_model=list[AuditEventOut])
def list_audit(
    req: Request,
    actor_id: UUID | None = Query(None),
    doc_id: UUID | None = Query(None),
    action: str | None = Query(None),
    outcome: str | None = Query(None),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    export: str | None = Query(None, description="Set to 'csv' for CSV export"),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    ip = get_client_ip(req)
    q = _base_audit_query(db, actor_id, doc_id, action, outcome, since, until)
    q = q.order_by(AuditEvent.id.desc())

    if export == "csv":
        rows = q.all()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "ts", "actor_id", "action", "doc_id", "target_user_id", "outcome", "ip", "detail", "hash"])
        for r in rows:
            w.writerow([r.id, r.ts, r.actor_id, r.action, r.doc_id, r.target_user_id, r.outcome, r.ip, r.detail, r.hash])
        buf.seek(0)
        log_event(db, action="audit_export_csv", outcome="allowed", actor_id=admin.id, ip=ip, detail={"row_count": len(rows)})
        return StreamingResponse(
            buf,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_events.csv"},
        )

    offset = (page - 1) * per_page
    events = q.offset(offset).limit(per_page).all()
    log_event(db, action="audit_list", outcome="allowed", actor_id=admin.id, ip=ip, detail={"page": page, "per_page": per_page})
    return events


@router.get("/activity")
def activity_summary(
    req: Request,
    since: datetime | None = Query(None),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    ip = get_client_ip(req)
    since = since or (datetime.now(timezone.utc) - timedelta(days=7))

    q = db.query(AuditEvent).filter(AuditEvent.ts >= since)
    total = q.count()

    action_counts = (
        db.query(AuditEvent.action, func.count().label("n"))
        .filter(AuditEvent.ts >= since)
        .group_by(AuditEvent.action)
        .order_by(func.count().desc())
        .all()
    )

    outcome_counts = (
        db.query(AuditEvent.outcome, func.count().label("n"))
        .filter(AuditEvent.ts >= since)
        .group_by(AuditEvent.outcome)
        .all()
    )

    top_actors = (
        db.query(AuditEvent.actor_id, func.count().label("n"))
        .filter(AuditEvent.ts >= since, AuditEvent.actor_id.isnot(None))
        .group_by(AuditEvent.actor_id)
        .order_by(func.count().desc())
        .limit(10)
        .all()
    )

    top_docs = (
        db.query(AuditEvent.doc_id, func.count().label("n"))
        .filter(AuditEvent.ts >= since, AuditEvent.doc_id.isnot(None))
        .group_by(AuditEvent.doc_id)
        .order_by(func.count().desc())
        .limit(10)
        .all()
    )

    alerts = _detect_alerts(db)

    log_event(db, action="admin_activity_view", outcome="allowed", actor_id=admin.id, ip=ip, detail={"since": since.isoformat()})

    return {
        "since": since.isoformat(),
        "total_events": total,
        "by_action": {r.action: r.n for r in action_counts},
        "by_outcome": {r.outcome: r.n for r in outcome_counts},
        "top_actors": [{"actor_id": str(r.actor_id), "count": r.n} for r in top_actors],
        "top_docs": [{"doc_id": str(r.doc_id), "count": r.n} for r in top_docs],
        "alerts": [a.model_dump() for a in alerts],
        "alert_count": len(alerts),
    }


@router.get("/activity/alerts", response_model=list[AlertItem])
def list_alerts(
    req: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    ip = get_client_ip(req)
    alerts = _detect_alerts(db)
    log_event(db, action="admin_alerts_view", outcome="allowed", actor_id=admin.id, ip=ip, detail={"alert_count": len(alerts)})
    return alerts


@router.get("/user-activity")
def user_activity(
    req: Request,
    since: datetime | None = Query(None),
    action: str | None = Query(None),
    actor_id: UUID | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Return audit events enriched with actor name/email, newest first."""
    ip = get_client_ip(req)
    since = since or (datetime.now(timezone.utc) - timedelta(days=30))

    q = db.query(AuditEvent, User).outerjoin(User, AuditEvent.actor_id == User.id)
    q = q.filter(AuditEvent.ts >= since)
    if action:
        q = q.filter(AuditEvent.action == action)
    if actor_id:
        q = q.filter(AuditEvent.actor_id == actor_id)

    total = q.count()
    rows = q.order_by(AuditEvent.id.desc()).offset(offset).limit(limit).all()

    events = []
    for ev, user in rows:
        events.append({
            "id": ev.id,
            "ts": ev.ts.isoformat() if ev.ts else None,
            "actor_id": str(ev.actor_id) if ev.actor_id else None,
            "actor_name": user.name if user else None,
            "actor_email": user.email if user else None,
            "actor_role": user.role if user else None,
            "action": ev.action,
            "doc_id": str(ev.doc_id) if ev.doc_id else None,
            "target_user_id": str(ev.target_user_id) if ev.target_user_id else None,
            "outcome": ev.outcome,
            "ip": ev.ip,
            "detail": ev.detail or {},
        })

    log_event(db, action="admin_activity_view", outcome="allowed", actor_id=admin.id, ip=ip,
              detail={"since": since.isoformat(), "action_filter": action})
    return {"total": total, "events": events, "since": since.isoformat()}
