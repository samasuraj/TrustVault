import os
import re
import hashlib
import unicodedata
from uuid import UUID
from fastapi import HTTPException, status
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.config import cfg

import io
import zipfile

MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB
MAX_DECOMPRESSED_RATIO = 25       # Max uncompressed-to-compressed ratio
MAX_TOTAL_UNCOMPRESSED = 50 * 1024 * 1024  # 50 MB uncompressed limit

ALLOWED_EXTENSIONS = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "txt": "text/plain",
    "csv": "text/csv",
}

DANGEROUS_EXTS = {
    "exe", "bat", "cmd", "sh", "ps1", "vbs", "js", "py", "php",
    "pl", "dll", "so", "bin", "msi", "com", "scr", "jar", "apk",
    "pif", "hta", "cpl", "msc", "wsf"
}

# Unicode directional override and zero-width characters
UNSAFE_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")

def sanitize_text(val: str | None) -> str | None:
    if val is None:
        return None
    cleaned = UNSAFE_CHARS.sub(" ", unicodedata.normalize("NFKD", str(val))).strip()
    return cleaned if cleaned else None

def _get_aes_key() -> bytes:
    return hashlib.sha256(cfg.encryption_key.encode()).digest()

def sanitize_filename(raw_name: str) -> str:
    if not raw_name or not raw_name.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Filename cannot be empty")

    # Normalize unicode
    name = unicodedata.normalize("NFKD", raw_name)

    # Strip dangerous characters
    name = UNSAFE_CHARS.sub("", name)

    # Neutralize path traversal
    name = name.replace("\\", "/").strip()
    name = os.path.basename(name)

    # Check for empty after sanitization
    if not name or name in (".", ".."):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename")

    # Check double extensions and executables
    parts = [p.lower() for p in name.split(".") if p]
    if len(parts) < 2:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Filename missing extension")

    ext = parts[-1]
    if ext == "jpeg":
        ext = "jpg"

    # Reject if any part contains dangerous extensions
    for part in parts[:-1]:
        if part in DANGEROUS_EXTS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Double extension with executable '{part}' is forbidden",
            )

    if ext in DANGEROUS_EXTS or ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Extension '{ext}' is not allowed",
        )

    return name

def verify_file_content(data: bytes, ext: str) -> str:
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File exceeds maximum allowed size of 20MB",
        )
    if len(data) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty files are not allowed")

    norm_ext = "jpg" if ext == "jpeg" else ext

    # Magic byte verification
    if norm_ext == "pdf":
        if not data.startswith(b"%PDF-"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid PDF magic bytes")
        if b"<html" in data[:1024].lower() or b"<!doctype html" in data[:1024].lower():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Disguised HTML polyglot in PDF")
    elif norm_ext == "png":
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid PNG magic bytes")
    elif norm_ext == "jpg":
        if not (data.startswith(b"\xff\xd8\xff")):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JPEG magic bytes")
    elif norm_ext in ("docx", "xlsx"):
        if not data.startswith(b"PK\x03\x04"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid {norm_ext.upper()} magic bytes")
        if len(data) > 64:
            if not zipfile.is_zipfile(io.BytesIO(data)):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Corrupted or invalid {norm_ext.upper()} archive",
                )
            try:
                with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                    namelist = zf.namelist()
                    if "[Content_Types].xml" not in namelist:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Disguised upload: missing OpenXML structures in {norm_ext.upper()}",
                        )
                    total_uncompressed = 0
                    for info in zf.infolist():
                        if ".." in info.filename or info.filename.startswith(("/", "\\")):
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Zip path traversal detected",
                            )
                        total_uncompressed += info.file_size
                        if total_uncompressed > MAX_TOTAL_UNCOMPRESSED:
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Decompression bomb detected: total uncompressed size exceeds limit",
                            )
                    if len(data) > 0 and (total_uncompressed / len(data)) > MAX_DECOMPRESSED_RATIO and total_uncompressed > 1024 * 1024:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Decompression bomb detected: excessive compression ratio",
                        )
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Corrupted or invalid {norm_ext.upper()} archive",
                )
    elif norm_ext in ("txt", "csv"):
        # Must be valid text without null bytes
        if b"\x00" in data:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid {norm_ext.upper()}: binary content detected")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                data.decode("latin-1")
            except Exception:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid text encoding in {norm_ext.upper()}")
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported file format")

    return ALLOWED_EXTENSIONS.get(norm_ext, "application/octet-stream")

def encrypt_bytes(data: bytes) -> tuple[int, str, bytes]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(_get_aes_key())
    ciphertext = aesgcm.encrypt(nonce, data, None)
    sha = hashlib.sha256(data).hexdigest()
    return len(data), sha, (nonce + ciphertext)

def decrypt_bytes(encrypted_data: bytes) -> bytes:
    if len(encrypted_data) < 28:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Corrupted storage object")
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(_get_aes_key())
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Decryption failed")

def encrypt_and_store(data: bytes, storage_key: UUID) -> tuple[int, str]:
    size, sha, payload = encrypt_bytes(data)
    storage_dir = getattr(cfg, "storage_dir", None)
    if storage_dir:
        try:
            os.makedirs(storage_dir, exist_ok=True)
            target_path = os.path.join(storage_dir, str(storage_key))
            with open(target_path, "wb") as f:
                f.write(payload)
        except Exception:
            pass
    return size, sha

def encrypt_and_store_data(data: bytes, storage_key: UUID) -> tuple[int, str, bytes]:
    size, sha, payload = encrypt_bytes(data)
    storage_dir = getattr(cfg, "storage_dir", None)
    if storage_dir:
        try:
            os.makedirs(storage_dir, exist_ok=True)
            target_path = os.path.join(storage_dir, str(storage_key))
            with open(target_path, "wb") as f:
                f.write(payload)
        except Exception:
            pass
    return size, sha, payload

def retrieve_and_decrypt(storage_key: UUID, version=None, db=None) -> bytes:
    # 1. If in-memory DocVersion object with file_data is provided
    if version is not None and getattr(version, "file_data", None) is not None:
        return decrypt_bytes(version.file_data)

    # 2. Query from database if db session is available
    if db is not None:
        try:
            from app.models import DocVersion
            v = db.query(DocVersion).filter(DocVersion.storage_key == storage_key).first()
            if v and v.file_data is not None:
                return decrypt_bytes(v.file_data)
        except Exception:
            pass
    else:
        # Fallback to query via SessionLocal
        try:
            from app.db import SessionLocal
            from app.models import DocVersion
            local_db = SessionLocal()
            try:
                v = local_db.query(DocVersion).filter(DocVersion.storage_key == storage_key).first()
                if v and v.file_data is not None:
                    return decrypt_bytes(v.file_data)
            finally:
                local_db.close()
        except Exception:
            pass

    # 3. Fallback to filesystem if storage_dir is configured
    storage_dir = getattr(cfg, "storage_dir", None)
    if storage_dir:
        target_path = os.path.join(storage_dir, str(storage_key))
        if os.path.exists(target_path):
            with open(target_path, "rb") as f:
                raw = f.read()
            return decrypt_bytes(raw)

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Storage object not found")
