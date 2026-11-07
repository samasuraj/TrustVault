import uuid
from datetime import datetime, timezone
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
    status,
)
from fastapi.responses import Response as RawResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import or_, and_, func
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import Document, DocVersion, Grant, User
from app.authz import authorize, record_audit, RequireDocAccess
from app.deps import get_current_user, get_client_ip, verify_csrf
from app.storage import (
    sanitize_filename,
    verify_file_content,
    encrypt_and_store,
    retrieve_and_decrypt,
)

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
        record_audit(db, action="doc_upload", outcome="denied", actor_id=user.id, ip=ip, detail={"reason": "not_owner_role"})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only document owners can upload files")

    raw_filename = file.filename or "document.bin"
    safe_filename = sanitize_filename(raw_filename)
    ext = safe_filename.rsplit(".", 1)[-1].lower()

    content = await file.read()
    mime = verify_file_content(content, ext)

    doc_id = uuid.uuid4()
    storage_key = uuid.uuid4()
    size, sha256 = encrypt_and_store(content, storage_key)

    now = datetime.now(timezone.utc)
    doc = Document(
        id=doc_id,
        owner_id=user.id,
        name=name.strip() if name and name.strip() else safe_filename,
        category=category.strip() if category else "General",
        description=description.strip() if description else None,
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

    record_audit(
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

    if name is not None and name.strip():
        doc.name = name.strip()
    if category is not None and category.strip():
        doc.category = category.strip()
    if description is not None:
        doc.description = description.strip() if description.strip() else None

    new_ver = None
    if file and file.filename:
        safe_filename = sanitize_filename(file.filename)
        ext = safe_filename.rsplit(".", 1)[-1].lower()
        content = await file.read()
        mime = verify_file_content(content, ext)

        storage_key = uuid.uuid4()
        size, sha256 = encrypt_and_store(content, storage_key)

        max_v = db.query(func.max(DocVersion.version_no)).filter(DocVersion.doc_id == doc.id).scalar() or 0
        new_v_no = max_v + 1

        new_ver = DocVersion(
            id=uuid.uuid4(),
            doc_id=doc.id,
            version_no=new_v_no,
            storage_key=storage_key,
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

    record_audit(
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

    record_audit(db, action="doc_delete", outcome="allowed", actor_id=user.id, doc_id=doc.id, ip=ip)
    return {"status": "deleted", "id": str(doc.id)}

@router.get("/{doc_id}/download")
def download_document(
    doc_id: UUID,
    req: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    ip = get_client_ip(req)
    doc = authorize(db, user, doc_id, "download", ip=ip)

    if not doc.current_version_id:
        record_audit(db, action="doc_download", outcome="denied", actor_id=user.id, doc_id=doc.id, ip=ip, detail={"reason": "no_versions"})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document content not found")

    version = db.query(DocVersion).filter(DocVersion.id == doc.current_version_id).first()
    if not version:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Version not found")

    decrypted_bytes = retrieve_and_decrypt(version.storage_key)

    record_audit(
        db,
        action="doc_download",
        outcome="allowed",
        actor_id=user.id,
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
