import uuid
from datetime import datetime, timezone, timedelta
from uuid import UUID
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    Response,
    UploadFile,
    File,
    Form,
    Query,
    status,
)
from fastapi.responses import Response as RawResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import or_, and_, func
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import Document, DocVersion, Grant, User, DownloadToken
from app.authz import authorize, RequireDocAccess
from app.audit import log_event
from app.deps import get_current_user, get_optional_current_user, get_client_ip, verify_csrf
from app.storage import (
    sanitize_filename,
    sanitize_text,
    verify_file_content,
    encrypt_and_store,
    encrypt_and_store_data,
    retrieve_and_decrypt,
)
from app.sharing_assistant import (
    generate_sharing_suggestions,
    get_suggestion_session,
    evaluate_decision,
)
from app.search_router import execute_search

router = APIRouter(tags=["documents"])

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

class GrantCreate(BaseModel):
    user_email: str
    perm: str
    expires_at: datetime | None = None

class GrantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    doc_id: UUID
    user_id: UUID
    user_email: str | None = None
    perm: str
    granted_by: UUID
    granted_at: datetime | None = None
    revoked_at: datetime | None = None
    expires_at: datetime | None = None

class DownloadTokenOut(BaseModel):
    token: str
    expires_at: str
    download_url: str

class SuggestedUserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: UUID
    email: str
    user_email: str
    name: str
    user_name: str
    suggested_perm: str
    perm: str
    reason: str

class SuggestAccessOut(BaseModel):
    sid: UUID
    suggestion_id: UUID
    doc_id: UUID
    suggestions: list[SuggestedUserOut]

class GrantPick(BaseModel):
    user_id: UUID | None = None
    user_email: str | None = None
    perm: str = "read"
    expires_at: datetime | None = None

class ConfirmSuggestionsIn(BaseModel):
    decision: str | None = None
    action: str | None = None
    grants: list[GrantPick] = []
    picks: list[GrantPick] = []
    decisions: list[GrantPick] = []

class ConfirmSuggestionsOut(BaseModel):
    status: str
    decision: str
    grants: list[GrantOut] = []

@router.post("", response_model=DocumentOut, status_code=status.HTTP_201_CREATED)
async def upload_document(
    req: Request,
    file: UploadFile = File(...),
    name: str = Form(None),
    category: str = Form("General"),
    description: str = Form(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
):
    ip = get_client_ip(req)
    if user.role not in ("owner", "admin"):
        log_event(db, action="doc_upload", outcome="denied", actor_id=user.id, ip=ip, detail={"reason": "not_owner_role"})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only document owners can upload files")

    raw_filename = file.filename or "document.bin"
    safe_filename = sanitize_filename(raw_filename)
    ext = safe_filename.rsplit(".", 1)[-1].lower()

    content = await file.read()
    mime = verify_file_content(content, ext)

    doc_id = uuid.uuid4()
    storage_key = uuid.uuid4()
    size, sha256, encrypted_blob = encrypt_and_store_data(content, storage_key)

    now = datetime.now(timezone.utc)
    clean_name = sanitize_text(name) or safe_filename
    clean_cat = sanitize_text(category) or "General"
    clean_desc = sanitize_text(description)

    doc = Document(
        id=doc_id,
        owner_id=user.id,
        name=clean_name,
        category=clean_cat,
        description=clean_desc,
        created_at=now,
        deleted_at=None,
    )
    db.add(doc)
    db.flush()

    ver = DocVersion(
        id=uuid.uuid4(),
        doc_id=doc.id,
        version_no=1,
        storage_key=storage_key,
        file_data=encrypted_blob,
        size=size,
        sha256=sha256,
        mime=mime,
        uploaded_by=user.id,
        created_at=now,
    )
    db.add(ver)
    db.flush()

    doc.current_version_id = ver.id
    db.commit()
    db.refresh(doc)

    log_event(
        db,
        action="doc_upload",
        outcome="allowed",
        actor_id=user.id,
        doc_id=doc.id,
        ip=ip,
        detail={"name": doc.name, "size": size, "sha256": sha256, "mime": mime},
    )

    out = DocumentOut.model_validate(doc)
    out.versions = [DocVersionOut.model_validate(ver)]
    return out

@router.get("", response_model=list[DocumentOut])
def list_documents(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    now = datetime.now(timezone.utc)
    docs = (
        db.query(Document)
        .outerjoin(Grant, Grant.doc_id == Document.id)
        .filter(
            Document.deleted_at.is_(None),
            or_(
                Document.owner_id == user.id,
                and_(
                    Grant.user_id == user.id,
                    Grant.revoked_at.is_(None),
                    or_(Grant.expires_at.is_(None), Grant.expires_at > now),
                ),
            ),
        )
        .distinct()
        .all()
    )

    results = []
    for d in docs:
        out = DocumentOut.model_validate(d)
        if d.owner_id == user.id:
            vers = db.query(DocVersion).filter(DocVersion.doc_id == d.id).order_by(DocVersion.version_no.desc()).all()
            out.versions = [DocVersionOut.model_validate(v) for v in vers]
        elif d.current_version_id:
            cur = db.query(DocVersion).filter(DocVersion.id == d.current_version_id).first()
            out.versions = [DocVersionOut.model_validate(cur)] if cur else []
        results.append(out)
    return results

@router.get("/search", response_model=list[DocumentOut])
def search_documents_in_doc_router(
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

@router.get("/{doc_id}", response_model=DocumentOut)
def get_document(
    doc_id: UUID,
    req: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip = get_client_ip(req)
    doc = authorize(db, user, doc_id, "read", ip=ip)

    out = DocumentOut.model_validate(doc)
    if doc.owner_id == user.id:
        vers = db.query(DocVersion).filter(DocVersion.doc_id == doc.id).order_by(DocVersion.version_no.desc()).all()
        out.versions = [DocVersionOut.model_validate(v) for v in vers]
    elif doc.current_version_id:
        cur = db.query(DocVersion).filter(DocVersion.id == doc.current_version_id).first()
        out.versions = [DocVersionOut.model_validate(cur)] if cur else []
    return out

@router.put("/{doc_id}", response_model=DocumentOut)
async def update_document(
    doc_id: UUID,
    req: Request,
    file: UploadFile = File(None),
    name: str = Form(None),
    category: str = Form(None),
    description: str = Form(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
):
    ip = get_client_ip(req)
    doc = authorize(db, user, doc_id, "edit", ip=ip)

    clean_name = sanitize_text(name)
    clean_cat = sanitize_text(category)
    clean_desc = sanitize_text(description)

    if clean_name is not None:
        doc.name = clean_name
    if clean_cat is not None:
        doc.category = clean_cat
    if description is not None:
        doc.description = clean_desc

    new_ver = None
    if file and file.filename:
        safe_filename = sanitize_filename(file.filename)
        ext = safe_filename.rsplit(".", 1)[-1].lower()
        content = await file.read()
        mime = verify_file_content(content, ext)

        storage_key = uuid.uuid4()
        size, sha256, encrypted_blob = encrypt_and_store_data(content, storage_key)

        max_v = db.query(func.max(DocVersion.version_no)).filter(DocVersion.doc_id == doc.id).scalar() or 0
        new_v_no = max_v + 1

        new_ver = DocVersion(
            id=uuid.uuid4(),
            doc_id=doc.id,
            version_no=new_v_no,
            storage_key=storage_key,
            file_data=encrypted_blob,
            size=size,
            sha256=sha256,
            mime=mime,
            uploaded_by=user.id,
        )
        db.add(new_ver)
        db.flush()
        doc.current_version_id = new_ver.id

    db.commit()
    db.refresh(doc)

    log_event(
        db,
        action="doc_edit",
        outcome="allowed",
        actor_id=user.id,
        doc_id=doc.id,
        ip=ip,
        detail={"name": doc.name, "new_version": new_ver.version_no if new_ver else None},
    )

    out = DocumentOut.model_validate(doc)
    if doc.owner_id == user.id:
        vers = db.query(DocVersion).filter(DocVersion.doc_id == doc.id).order_by(DocVersion.version_no.desc()).all()
        out.versions = [DocVersionOut.model_validate(v) for v in vers]
    elif doc.current_version_id:
        cur = db.query(DocVersion).filter(DocVersion.id == doc.current_version_id).first()
        out.versions = [DocVersionOut.model_validate(cur)] if cur else []
    return out

@router.delete("/{doc_id}")
def delete_document(
    doc_id: UUID,
    req: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
):
    ip = get_client_ip(req)
    doc = authorize(db, user, doc_id, "delete", ip=ip)

    doc.deleted_at = datetime.now(timezone.utc)
    db.commit()

    log_event(db, action="doc_delete", outcome="allowed", actor_id=user.id, doc_id=doc.id, ip=ip)
    return {"status": "deleted", "id": str(doc.id)}

@router.post("/{doc_id}/grants", response_model=GrantOut, status_code=status.HTTP_201_CREATED)
def create_grant(
    doc_id: UUID,
    payload: GrantCreate,
    req: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
):
    ip = get_client_ip(req)
    doc = authorize(db, user, doc_id, "share", ip=ip)

    if payload.perm not in ("read", "edit"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Permission must be 'read' or 'edit'")

    target_user = db.query(User).filter(User.email == payload.user_email.strip().lower()).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user not found")

    now = datetime.now(timezone.utc)
    active_grants = (
        db.query(Grant)
        .filter(
            Grant.doc_id == doc.id,
            Grant.user_id == target_user.id,
            Grant.revoked_at.is_(None),
        )
        .all()
    )
    for ag in active_grants:
        ag.revoked_at = now

    grant = Grant(
        id=uuid.uuid4(),
        doc_id=doc.id,
        user_id=target_user.id,
        perm=payload.perm,
        granted_by=user.id,
        granted_at=now,
        expires_at=payload.expires_at,
    )
    db.add(grant)
    db.commit()
    db.refresh(grant)

    log_event(
        db,
        action="grant_create",
        outcome="allowed",
        actor_id=user.id,
        doc_id=doc.id,
        target_user_id=target_user.id,
        ip=ip,
        detail={"perm": grant.perm, "expires_at": grant.expires_at.isoformat() if grant.expires_at else None},
    )

    out = GrantOut.model_validate(grant)
    out.user_email = target_user.email
    return out

@router.delete("/{doc_id}/grants/{gid}")
def revoke_grant(
    doc_id: UUID,
    gid: UUID,
    req: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
):
    ip = get_client_ip(req)
    doc = authorize(db, user, doc_id, "share", ip=ip)

    grant = db.query(Grant).filter(Grant.id == gid, Grant.doc_id == doc.id).first()
    if not grant:
        log_event(
            db,
            action="grant_revoke",
            outcome="denied",
            actor_id=user.id,
            doc_id=doc.id,
            ip=ip,
            detail={"reason": "grant_not_found", "grant_id": str(gid)},
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Grant not found")

    now = datetime.now(timezone.utc)
    grant.revoked_at = now

    db.query(DownloadToken).filter(
        DownloadToken.doc_id == doc.id,
        DownloadToken.user_id == grant.user_id,
        DownloadToken.used_at.is_(None),
    ).update({"used_at": now})

    db.commit()

    log_event(
        db,
        action="grant_revoke",
        outcome="allowed",
        actor_id=user.id,
        doc_id=doc.id,
        target_user_id=grant.user_id,
        ip=ip,
        detail={"grant_id": str(grant.id)},
    )
    return {"status": "revoked", "id": str(grant.id)}

@router.get("/{doc_id}/grants", response_model=list[GrantOut])
def list_grants(
    doc_id: UUID,
    req: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip = get_client_ip(req)
    doc = authorize(db, user, doc_id, "share", ip=ip)

    grants = (
        db.query(Grant, User.email)
        .join(User, User.id == Grant.user_id)
        .filter(Grant.doc_id == doc.id)
        .order_by(Grant.granted_at.desc())
        .all()
    )

    log_event(db, action="grants_list", outcome="allowed", actor_id=user.id, doc_id=doc.id, ip=ip)

    res = []
    for g, email in grants:
        out = GrantOut.model_validate(g)
        out.user_email = email
        res.append(out)
    return res

@router.post("/{doc_id}/download-token", response_model=DownloadTokenOut)
def issue_download_token(
    doc_id: UUID,
    req: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
):
    ip = get_client_ip(req)
    doc = authorize(db, user, doc_id, "download", ip=ip)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=60)
    tok = DownloadToken(
        id=uuid.uuid4(),
        doc_id=doc.id,
        user_id=user.id,
        expires_at=expires_at,
        used_at=None,
    )
    db.add(tok)
    db.commit()
    db.refresh(tok)

    log_event(
        db,
        action="token_issue",
        outcome="allowed",
        actor_id=user.id,
        doc_id=doc.id,
        ip=ip,
        detail={"token_id": str(tok.id), "expires_at": expires_at.isoformat()},
    )

    return DownloadTokenOut(
        token=str(tok.id),
        expires_at=expires_at.isoformat(),
        download_url=f"/documents/{doc.id}/download?token={tok.id}",
    )

@router.get("/{doc_id}/download")
def download_document(
    doc_id: UUID,
    req: Request,
    token: UUID | None = None,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_current_user),
):
    ip = get_client_ip(req)
    if token is not None:
        tok = (
            db.query(DownloadToken)
            .filter(DownloadToken.id == token, DownloadToken.doc_id == doc_id)
            .first()
        )
        now = datetime.now(timezone.utc)
        if not tok or tok.used_at is not None or tok.expires_at <= now:
            log_event(
                db,
                action="token_redeem",
                outcome="denied",
                doc_id=doc_id,
                ip=ip,
                detail={"reason": "invalid_or_expired_token", "token": str(token)},
            )
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

        tok_user = db.query(User).filter(User.id == tok.user_id).first()
        if not tok_user or not tok_user.is_active:
            log_event(
                db,
                action="token_redeem",
                outcome="denied",
                doc_id=doc_id,
                ip=ip,
                detail={"reason": "user_inactive_or_missing", "token": str(token)},
            )
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

        if user and user.id != tok.user_id:
            log_event(
                db,
                action="token_redeem",
                outcome="denied",
                actor_id=user.id,
                doc_id=doc_id,
                ip=ip,
                detail={"reason": "token_user_mismatch", "token": str(token)},
            )
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

        doc = authorize(db, tok_user, doc_id, "download", ip=ip)

        tok.used_at = now
        db.commit()

        log_event(
            db,
            action="token_redeem",
            outcome="allowed",
            actor_id=tok_user.id,
            doc_id=doc.id,
            ip=ip,
            detail={"token_id": str(tok.id)},
        )
        active_user = tok_user
    else:
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        doc = authorize(db, user, doc_id, "download", ip=ip)
        active_user = user

    if not doc.current_version_id:
        log_event(db, action="doc_download", outcome="denied", actor_id=active_user.id, doc_id=doc.id, ip=ip, detail={"reason": "no_versions"})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document content not found")

    version = db.query(DocVersion).filter(DocVersion.id == doc.current_version_id).first()
    if not version:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Version not found")

    decrypted_bytes = retrieve_and_decrypt(version.storage_key, version=version, db=db)

    log_event(
        db,
        action="doc_download",
        outcome="allowed",
        actor_id=active_user.id,
        doc_id=doc.id,
        ip=ip,
        detail={"version_no": version.version_no, "size": version.size},
    )

    clean_filename = sanitize_filename(doc.name)
    headers = {
        "Content-Disposition": f'attachment; filename="{clean_filename}"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    }

    return RawResponse(
        content=decrypted_bytes,
        media_type=version.mime,
        headers=headers,
    )

@router.post("/{doc_id}/suggest-access", response_model=SuggestAccessOut)
def suggest_access(
    doc_id: UUID,
    req: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
):
    ip = get_client_ip(req)
    doc = authorize(db, user, doc_id, "share", ip=ip)

    sid, suggestions = generate_sharing_suggestions(db, doc, user)

    log_event(
        db,
        action="suggest_access",
        outcome="allowed",
        actor_id=user.id,
        doc_id=doc.id,
        ip=ip,
        detail={"sid": str(sid), "suggestions": suggestions},
    )

    return SuggestAccessOut(
        sid=sid,
        suggestion_id=sid,
        doc_id=doc.id,
        suggestions=[SuggestedUserOut(**s) for s in suggestions],
    )

@router.post("/{doc_id}/suggestions/{sid}/confirm", response_model=ConfirmSuggestionsOut)
def confirm_suggestions(
    doc_id: UUID,
    sid: UUID,
    payload: ConfirmSuggestionsIn,
    req: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _csrf: None = Depends(verify_csrf),
):
    ip = get_client_ip(req)
    doc = authorize(db, user, doc_id, "share", ip=ip)

    session = get_suggestion_session(db, sid, doc.id)
    if not session:
        log_event(
            db,
            action="suggest_confirm",
            outcome="denied",
            actor_id=user.id,
            doc_id=doc.id,
            ip=ip,
            detail={"reason": "suggestion_not_found", "sid": str(sid)},
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Suggestion session not found")

    picks = payload.grants or payload.picks or payload.decisions or []
    explicit_act = payload.decision or payload.action
    raw_decision = evaluate_decision(
        orig_suggestions=session.get("suggestions", []),
        picked_grants=[p.model_dump() for p in picks],
        explicit_action=explicit_act,
    )

    now = datetime.now(timezone.utc)
    created_grants = []

    if raw_decision != "rejected" and picks:
        for p in picks:
            if p.perm not in ("read", "edit"):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Permission must be 'read' or 'edit'")

            target_user = None
            if p.user_email and p.user_email.strip():
                target_user = db.query(User).filter(User.email == p.user_email.strip().lower()).first()
            elif p.user_id:
                target_user = db.query(User).filter(User.id == p.user_id).first()

            if not target_user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Target user not found: {p.user_email or p.user_id}")

            try:
                active_grants = (
                    db.query(Grant)
                    .filter(
                        Grant.doc_id == doc.id,
                        Grant.user_id == target_user.id,
                        Grant.revoked_at.is_(None),
                    )
                    .all()
                )
                for ag in active_grants:
                    ag.revoked_at = now
            except Exception:
                pass

            grant = Grant(
                id=uuid.uuid4(),
                doc_id=doc.id,
                user_id=target_user.id,
                perm=p.perm,
                granted_by=user.id,
                granted_at=now,
                expires_at=p.expires_at,
            )
            db.add(grant)
            created_grants.append((grant, target_user.email))

            log_event(
                db,
                action="grant_create",
                outcome="allowed",
                actor_id=user.id,
                doc_id=doc.id,
                target_user_id=target_user.id,
                ip=ip,
                detail={"perm": grant.perm, "via_suggestion": str(sid)},
            )

        db.commit()

    log_event(
        db,
        action="suggest_confirm",
        outcome="allowed",
        actor_id=user.id,
        doc_id=doc.id,
        ip=ip,
        detail={
            "sid": str(sid),
            "decision": raw_decision,
            "picked": [p.model_dump(mode="json") for p in picks],
            "suggested": session.get("suggestions", []),
        },
    )

    out_grants = []
    for g, email in created_grants:
        try:
            db.refresh(g)
        except Exception:
            pass
        g_out = GrantOut.model_validate(g)
        g_out.user_email = email
        out_grants.append(g_out)

    return ConfirmSuggestionsOut(
        status="confirmed",
        decision=raw_decision,
        grants=out_grants,
    )
