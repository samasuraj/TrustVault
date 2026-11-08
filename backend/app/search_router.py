import re
from datetime import datetime, timezone
from uuid import UUID
from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import or_, and_
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import Document, DocVersion, Grant, User
from app.deps import get_current_user, get_client_ip
from app.audit import log_event

class DocVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    version_no: int
    size: int
    sha256: str
    mime: str
    uploaded_by: UUID
    created_at: datetime | None = None

class DocumentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    owner_id: UUID
    name: str
    category: str
    description: str | None = None
    created_at: datetime | None = None
    current_version_id: UUID | None = None
    versions: list[DocVersionOut] = []

router = APIRouter(tags=["search"])

def parse_date_param(d: str | None, is_end: bool = False) -> datetime | None:
    if not d:
        return None
    d = d.strip()
    try:
        if len(d) == 10 and d.count("-") == 2:
            dt = datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if is_end:
                dt = dt.replace(hour=23, minute=59, second=59, microsecond=999999)
            return dt
        if d.endswith("Z"):
            d = d[:-1] + "+00:00"
        return datetime.fromisoformat(d)
    except Exception:
        return None

def execute_search(
    db: Session,
    user: User,
    ip: str | None = None,
    name: str | None = None,
    owner: str | None = None,
    category: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    date_range: str | None = None,
) -> list[DocumentOut]:
    now = datetime.now(timezone.utc)

    # Base query: join Document with Grant and User (for owner lookup)
    query = (
        db.query(Document)
        .outerjoin(Grant, Grant.doc_id == Document.id)
        .join(User, User.id == Document.owner_id)
    )

    # Permission filtering is strictly part of the SQL WHERE clause
    # Ensures no docs the user cannot access are ever returned or counted
    access_clause = or_(
        Document.owner_id == user.id,
        and_(
            Grant.user_id == user.id,
            Grant.revoked_at.is_(None),
            or_(Grant.expires_at.is_(None), Grant.expires_at > now),
        ),
    )
    query = query.filter(Document.deleted_at.is_(None), access_clause)

    # Filter: name (ILIKE)
    if name and name.strip():
        query = query.filter(Document.name.ilike(f"%{name.strip()}%"))

    # Filter: category (ILIKE)
    if category and category.strip():
        query = query.filter(Document.category.ilike(f"%{category.strip()}%"))

    # Filter: owner (email, name, or UUID)
    if owner and owner.strip():
        o_str = owner.strip()
        try:
            o_uuid = UUID(o_str)
            query = query.filter(Document.owner_id == o_uuid)
        except (ValueError, TypeError):
            query = query.filter(
                or_(
                    User.email.ilike(f"%{o_str}%"),
                    User.name.ilike(f"%{o_str}%"),
                )
            )

    # Filter: date range
    s_date = start_date or from_date
    e_date = end_date or to_date
    if date_range and date_range.strip():
        parts = re.split(r"\.\.|,", date_range.strip())
        if len(parts) >= 2:
            s_date = s_date or parts[0]
            e_date = e_date or parts[1]
        elif len(parts) == 1:
            s_date = s_date or parts[0]

    dt_start = parse_date_param(s_date, is_end=False)
    dt_end = parse_date_param(e_date, is_end=True)

    if dt_start:
        query = query.filter(Document.created_at >= dt_start)
    if dt_end:
        query = query.filter(Document.created_at <= dt_end)

    docs = query.distinct().all()

    results = []
    for d in docs:
        out = DocumentOut.model_validate(d)
        if d.owner_id == user.id:
            try:
                vers = db.query(DocVersion).filter(DocVersion.doc_id == d.id).order_by(DocVersion.version_no.desc()).all()
                out.versions = [DocVersionOut.model_validate(v) for v in vers]
            except Exception:
                out.versions = []
        elif d.current_version_id:
            try:
                cur = db.query(DocVersion).filter(DocVersion.id == d.current_version_id).first()
                out.versions = [DocVersionOut.model_validate(cur)] if cur else []
            except Exception:
                out.versions = []
        results.append(out)

    log_event(
        db,
        action="doc_search",
        outcome="allowed",
        actor_id=user.id,
        ip=ip,
        detail={
            "query": {
                "name": name,
                "owner": owner,
                "category": category,
                "start_date": s_date,
                "end_date": e_date,
            },
            "results_count": len(results),
        },
    )

    return results


@router.get("/search", response_model=list[DocumentOut])
def search_documents(
    req: Request,
    name: str | None = Query(None),
    owner: str | None = Query(None),
    category: str | None = Query(None),
    start_date: str | None = Query(None),
    end_date: str | None = Query(None),
    from_date: str | None = Query(None),
    to_date: str | None = Query(None),
    date_range: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip = get_client_ip(req)
    return execute_search(
        db=db,
        user=user,
        ip=ip,
        name=name,
        owner=owner,
        category=category,
        start_date=start_date,
        end_date=end_date,
        from_date=from_date,
        to_date=to_date,
        date_range=date_range,
    )
