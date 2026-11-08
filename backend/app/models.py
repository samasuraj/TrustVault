import uuid
from sqlalchemy import (
    Column,
    String,
    Integer,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    UniqueConstraint,
    LargeBinary,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, ENUM
from sqlalchemy.sql import func
from app.db import Base

role_enum = ENUM("admin", "owner", "viewer", name="user_role", create_type=False)
perm_enum = ENUM("read", "edit", name="grant_perm", create_type=False)
outcome_enum = ENUM("allowed", "denied", name="audit_outcome", create_type=False)

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    pw_hash = Column(String, nullable=False)
    role = Column(role_enum, nullable=False, default="viewer")
    token_version = Column(Integer, nullable=False, default=1)
    is_active = Column(Boolean, nullable=False, default=True)
    failed_logins = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

class Document(Base):
    __tablename__ = "documents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    name = Column(String, nullable=False)
    category = Column(String, nullable=False)
    description = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    current_version_id = Column(
        UUID(as_uuid=True),
        ForeignKey("doc_versions.id", use_alter=True, name="fk_documents_current_version"),
        nullable=True,
    )

    __table_args__ = (
        Index("idx_docs_name", "name"),
        Index("idx_docs_category", "category"),
        Index("idx_docs_created_at", "created_at"),
        Index("idx_docs_owner_id", "owner_id"),
    )

class DocVersion(Base):
    __tablename__ = "doc_versions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    doc_id = Column(UUID(as_uuid=True), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    version_no = Column(Integer, nullable=False)
    storage_key = Column(UUID(as_uuid=True), default=uuid.uuid4, nullable=False)
    file_data = Column(LargeBinary, nullable=True)
    size = Column(BigInteger, nullable=False)
    sha256 = Column(String(64), nullable=False)
    mime = Column(String(255), nullable=False)
    uploaded_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("doc_id", "version_no", name="uq_doc_version"),
    )

class Grant(Base):
    __tablename__ = "grants"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    doc_id = Column(UUID(as_uuid=True), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    perm = Column(perm_enum, nullable=False)
    granted_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    granted_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)

class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    ts = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    actor_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(String, nullable=False)
    doc_id = Column(UUID(as_uuid=True), ForeignKey("documents.id", ondelete="SET NULL"), nullable=True)
    target_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    outcome = Column(outcome_enum, nullable=False)
    ip = Column(String, nullable=True)
    detail = Column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    prev_hash = Column(String(64), nullable=True)
    hash = Column(String(64), nullable=False)

class DownloadToken(Base):
    __tablename__ = "download_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    doc_id = Column(UUID(as_uuid=True), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
