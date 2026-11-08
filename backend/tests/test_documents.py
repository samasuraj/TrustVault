import io
import os
import uuid
import tempfile
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db import get_db
from app.deps import get_current_user
from app.models import Document, DocVersion, Grant, User, AuditEvent
from app.storage import (
    sanitize_filename,
    verify_file_content,
    encrypt_and_store,
    retrieve_and_decrypt,
    MAX_FILE_SIZE,
)
from app.config import cfg

@pytest.fixture(autouse=True)
def setup_temp_storage(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setattr(cfg, "storage_dir", tmpdir)
        yield tmpdir

def test_filename_sanitization_and_rejections():
    # Path traversal neutralized
    assert sanitize_filename("../../../etc/passwd.pdf") == "passwd.pdf"
    assert sanitize_filename("..\\..\\windows\\system32.png") == "system32.png"

    # Unicode trick (Right-to-Left Override \u202E) stripped
    assert sanitize_filename("financial_report\u202eexe.pdf") == "financial_reportexe.pdf"

    # Double extension with executable rejected
    with pytest.raises(Exception):
        sanitize_filename("invoice.exe.pdf")
    with pytest.raises(Exception):
        sanitize_filename("payload.sh.png")
    with pytest.raises(Exception):
        sanitize_filename("virus.pdf.exe")

    # Extension not in allowlist rejected
    with pytest.raises(Exception):
        sanitize_filename("notes.html")
    with pytest.raises(Exception):
        sanitize_filename("script.py")

    # Empty filename rejected
    with pytest.raises(Exception):
        sanitize_filename("")

def test_magic_byte_verification():
    # Valid PDF
    valid_pdf = b"%PDF-1.4 valid content"
    assert verify_file_content(valid_pdf, "pdf") == "application/pdf"

    # Fake PDF (text pretending to be PDF) rejected
    fake_pdf = b"This is just plain text without PDF header"
    with pytest.raises(Exception):
        verify_file_content(fake_pdf, "pdf")

    # Valid PNG
    valid_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    assert verify_file_content(valid_png, "png") == "image/png"

    # Fake PNG rejected
    with pytest.raises(Exception):
        verify_file_content(b"not a png image", "png")

    # Valid JPEG
    valid_jpg = b"\xff\xd8\xff\xe0\x00\x10JFIF"
    assert verify_file_content(valid_jpg, "jpg") == "image/jpeg"

    # Valid DOCX / XLSX (ZIP container header)
    valid_zip = b"PK\x03\x04\x14\x00\x06\x00"
    assert verify_file_content(valid_zip, "docx") == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

    # File exceeding 20MB rejected
    too_large = b"A" * (MAX_FILE_SIZE + 1)
    with pytest.raises(Exception):
        verify_file_content(too_large, "txt")

def test_aes_256_gcm_encryption_at_rest():
    raw_data = b"Confidential Financial Audit Report - Strictly Secret"
    storage_key = uuid.uuid4()

    size, sha256 = encrypt_and_store(raw_data, storage_key)
    assert size == len(raw_data)

    target_path = os.path.join(cfg.storage_dir, str(storage_key))
    assert os.path.exists(target_path)

    # File on disk MUST NOT contain plaintext
    with open(target_path, "rb") as f:
        disk_bytes = f.read()
    assert raw_data not in disk_bytes

    # Decrypting returns exact plaintext
    decrypted = retrieve_and_decrypt(storage_key)
    assert decrypted == raw_data

def test_document_upload_success():
    owner = User(id=uuid.uuid4(), email="owner@tv.local", name="Owner", pw_hash="h", role="owner", is_active=True, token_version=1)
    mock_db = MagicMock()
    mock_db.query.return_value.order_by.return_value.first.return_value = None

    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_current_user] = lambda: owner

    c = TestClient(app)

    file_bytes = b"%PDF-1.5 test document content for upload"
    files = {"file": ("report.pdf", io.BytesIO(file_bytes), "application/pdf")}
    data = {"name": "Audit Report", "category": "Compliance", "description": "Yearly audit"}

    # CSRF headers
    c.cookies.set("tv_csrf", "csrf-token")
    headers = {"X-CSRF-Token": "csrf-token"}

    res = c.post("/api/documents", files=files, data=data, headers=headers)
    assert res.status_code == 201
    res_data = res.json()
    assert res_data["name"] == "Audit Report"
    assert res_data["category"] == "Compliance"
    assert len(res_data["versions"]) == 1
    assert res_data["versions"][0]["version_no"] == 1

    app.dependency_overrides.clear()

def test_stranger_gets_404_on_every_endpoint():
    owner = User(id=uuid.uuid4(), email="owner@tv.local", name="Owner", pw_hash="h", role="owner", is_active=True, token_version=1)
    stranger = User(id=uuid.uuid4(), email="stranger@tv.local", name="Stranger", pw_hash="h", role="viewer", is_active=True, token_version=1)

    doc_id = uuid.uuid4()
    ver_id = uuid.uuid4()
    doc = Document(id=doc_id, owner_id=owner.id, name="Secret.pdf", category="Finance", current_version_id=ver_id, deleted_at=None)

    mock_db = MagicMock()
    def mock_query(model, *args, **kwargs):
        q = MagicMock()
        if model == Document:
            q.filter.return_value.first.return_value = doc
        elif model == Grant:
            q.filter.return_value.first.return_value = None
        elif model == AuditEvent:
            q.order_by.return_value.first.return_value = None
        else:
            q.filter.return_value.first.return_value = None
        return q

    mock_db.query.side_effect = mock_query

    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_current_user] = lambda: stranger

    c = TestClient(app)
    c.cookies.set("tv_csrf", "token")
    headers = {"X-CSRF-Token": "token"}

    # GET /documents/{id} -> 404
    assert c.get(f"/api/documents/{doc_id}").status_code == 404

    # GET /documents/{id}/download -> 404
    assert c.get(f"/api/documents/{doc_id}/download").status_code == 404

    # PUT /documents/{id} -> 404
    assert c.put(f"/api/documents/{doc_id}", data={"name": "hacked"}, headers=headers).status_code == 404

    # DELETE /documents/{id} -> 404
    assert c.delete(f"/api/documents/{doc_id}", headers=headers).status_code == 404

    app.dependency_overrides.clear()

def test_download_decryption_and_headers():
    owner = User(id=uuid.uuid4(), email="owner@tv.local", name="Owner", pw_hash="h", role="owner", is_active=True, token_version=1)
    doc_id = uuid.uuid4()
    storage_key = uuid.uuid4()
    ver_id = uuid.uuid4()

    raw_content = b"%PDF-1.4 encrypted content on disk test"
    size, sha = encrypt_and_store(raw_content, storage_key)

    doc = Document(id=doc_id, owner_id=owner.id, name="Financials.pdf", category="Finance", current_version_id=ver_id, deleted_at=None)
    ver = DocVersion(id=ver_id, doc_id=doc_id, version_no=1, storage_key=storage_key, size=size, sha256=sha, mime="application/pdf", uploaded_by=owner.id)

    mock_db = MagicMock()
    def mock_query(model, *args, **kwargs):
        q = MagicMock()
        if model == Document:
            q.filter.return_value.first.return_value = doc
        elif model == DocVersion:
            q.filter.return_value.first.return_value = ver
        elif model == AuditEvent:
            q.order_by.return_value.first.return_value = None
        else:
            q.filter.return_value.first.return_value = None
        return q

    mock_db.query.side_effect = mock_query

    app.dependency_overrides[get_db] = lambda: mock_db
    app.dependency_overrides[get_current_user] = lambda: owner

    c = TestClient(app)
    res = c.get(f"/api/documents/{doc_id}/download")
    assert res.status_code == 200
    assert res.content == raw_content
    # Non-negotiable download headers
    assert "attachment" in res.headers["content-disposition"]
    assert res.headers["x-content-type-options"] == "nosniff"
    assert res.headers["cache-control"] == "no-store"

    app.dependency_overrides.clear()

def test_versioning_old_versions_hidden_from_non_owner():
    owner = User(id=uuid.uuid4(), email="owner@tv.local", name="Owner", pw_hash="h", role="owner", is_active=True, token_version=1)
    viewer = User(id=uuid.uuid4(), email="viewer@tv.local", name="Viewer", pw_hash="h", role="viewer", is_active=True, token_version=1)

    doc_id = uuid.uuid4()
    v1_id = uuid.uuid4()
    v2_id = uuid.uuid4()

    doc = Document(
        id=doc_id,
        owner_id=owner.id,
        name="Doc.pdf",
        category="Tech",
        current_version_id=v2_id,
        created_at=datetime.now(timezone.utc),
        deleted_at=None,
    )
    v1 = DocVersion(id=v1_id, doc_id=doc_id, version_no=1, storage_key=uuid.uuid4(), size=100, sha256="s1", mime="application/pdf", uploaded_by=owner.id, created_at=datetime.now(timezone.utc))
    v2 = DocVersion(id=v2_id, doc_id=doc_id, version_no=2, storage_key=uuid.uuid4(), size=200, sha256="s2", mime="application/pdf", uploaded_by=owner.id, created_at=datetime.now(timezone.utc))

    grant = Grant(id=uuid.uuid4(), doc_id=doc_id, user_id=viewer.id, perm="read", granted_by=owner.id, granted_at=datetime.now(timezone.utc), revoked_at=None, expires_at=None)

    mock_db = MagicMock()
    def mock_query(model, *args, **kwargs):
        q = MagicMock()
        if model == Document:
            q.filter.return_value.first.return_value = doc
        elif model == Grant:
            q.filter.return_value.first.return_value = grant
        elif model == DocVersion:
            # When owner asks: all versions. When viewer asks: current version
            q.filter.return_value.order_by.return_value.all.return_value = [v2, v1]
            q.filter.return_value.first.return_value = v2
        elif model == AuditEvent:
            q.order_by.return_value.first.return_value = None
        else:
            q.filter.return_value.first.return_value = None
        return q

    mock_db.query.side_effect = mock_query
    app.dependency_overrides[get_db] = lambda: mock_db

    # 1. Owner sees both version 1 and 2
    app.dependency_overrides[get_current_user] = lambda: owner
    c = TestClient(app)
    owner_res = c.get(f"/api/documents/{doc_id}")
    assert owner_res.status_code == 200
    assert len(owner_res.json()["versions"]) == 2

    # 2. Granted viewer sees ONLY the current version (v2), old version (v1) hidden
    app.dependency_overrides[get_current_user] = lambda: viewer
    viewer_res = c.get(f"/api/documents/{doc_id}")
    assert viewer_res.status_code == 200
    assert len(viewer_res.json()["versions"]) == 1
    assert viewer_res.json()["versions"][0]["version_no"] == 2

    app.dependency_overrides.clear()


def test_postgres_bytea_storage_and_retrieval(monkeypatch):
    """Verify that file data is stored encrypted in bytea and decrypted without disk storage."""
    from app.storage import encrypt_and_store_data

    # Ensure storage_dir is None (simulating serverless / no disk)
    monkeypatch.setattr(cfg, "storage_dir", None)

    secret_content = b"%PDF-1.5 Confidential Financial Record"
    key = uuid.uuid4()

    size, sha256, encrypted_blob = encrypt_and_store_data(secret_content, key)
    assert size == len(secret_content)
    assert secret_content not in encrypted_blob

    # Create DocVersion with encrypted_blob in file_data
    ver = DocVersion(
        id=uuid.uuid4(),
        doc_id=uuid.uuid4(),
        version_no=1,
        storage_key=key,
        file_data=encrypted_blob,
        size=size,
        sha256=sha256,
        mime="application/pdf",
        uploaded_by=uuid.uuid4(),
    )

    # retrieve_and_decrypt from version.file_data directly
    decrypted = retrieve_and_decrypt(key, version=ver)
    assert decrypted == secret_content

