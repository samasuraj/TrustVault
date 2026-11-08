# TrustVault API Reference

This document provides a comprehensive specification of all HTTP endpoints exposed by the TrustVault backend, including HTTP methods, paths, authentication and CSRF requirements, payload formats, and **exactly who is authorized to call each endpoint**.

---

## Global Authentication & Security Rules

1. **Authentication**:
   - Primary: HTTP-only session cookie named `tv_access` containing a signed JWT (15-minute expiration).
   - Alternate: Standard `Authorization: Bearer <JWT>` HTTP header.
2. **CSRF Protection**:
   - All state-changing methods (`POST`, `PUT`, `PATCH`, `DELETE`) require a request header `X-CSRF-Token` matching the value in the `tv_csrf` cookie.
3. **Deny-by-Default Anti-Enumeration**:
   - Accessing a document without authorization returns **HTTP 404** (never 403), ensuring document existence and metadata are never leaked to unauthorized users.
4. **Separation of Duties**:
   - The `admin` role has zero implicit access to view or download document contents. Admin privileges apply only to user provisioning, audit inspection, and system metrics.

---

## 1. Authentication & User Management (`/api/auth`)

### `POST /api/auth/login`
- **Who May Call**: Public / Unauthenticated callers.
- **Rate Limit**: Max 10 attempts per minute per IP; accounts lock for 15 minutes after 5 consecutive failed attempts.
- **Request Body** (`application/json`):
  ```json
  {
    "email": "alice.owner@trustvault.local",
    "password": "AlicePassword123!"
  }
  ```
- **Response** (`200 OK`): Sets HTTP-only `tv_access` cookie and `tv_csrf` cookie.
  ```json
  {
    "status": "authenticated",
    "user": {
      "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "email": "alice.owner@trustvault.local",
      "name": "Alice Vance",
      "role": "owner",
      "is_active": true,
      "token_version": 1
    }
  }
  ```

---

### `POST /api/auth/logout`
- **Who May Call**: Any authenticated user (`admin`, `owner`, `viewer`).
- **Response** (`200 OK`): Clears `tv_access` and `tv_csrf` cookies.
  ```json
  {
    "status": "logged_out"
  }
  ```

---

### `GET /api/auth/me`
- **Who May Call**: Any authenticated user (`admin`, `owner`, `viewer`).
- **Response** (`200 OK`): Returns current user profile.
  ```json
  {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "email": "alice.owner@trustvault.local",
    "name": "Alice Vance",
    "role": "owner",
    "is_active": true,
    "token_version": 1
  }
  ```

---

### `POST /api/auth/register`
- **Who May Call**: **Administrator only (`role: admin`)**.
- **Request Body** (`application/json`):
  ```json
  {
    "email": "new.user@trustvault.local",
    "name": "New User",
    "password": "SecurePassword123!",
    "role": "viewer"
  }
  ```
- **Response** (`200 OK`):
  ```json
  {
    "id": "e0b8e734-4531-41b4-b816-77894a8e2cb9",
    "email": "new.user@trustvault.local",
    "name": "New User",
    "role": "viewer",
    "is_active": true,
    "token_version": 1
  }
  ```

---

### `POST /api/auth/users/{user_id}/disable`
- **Who May Call**: **Administrator only (`role: admin`)**.
- **Description**: Sets `is_active = False` and bumps `token_version`, immediately invalidating all active sessions for the targeted user.
- **Response** (`200 OK`):
  ```json
  {
    "status": "disabled",
    "user_id": "e0b8e734-4531-41b4-b816-77894a8e2cb9"
  }
  ```

---

### `POST /api/auth/users/{user_id}/bump-version`
- **Who May Call**: **Administrator only (`role: admin`)**.
- **Description**: Increments `token_version`, instantly revoking all outstanding JWT tokens for the user without disabling their account.
- **Response** (`200 OK`):
  ```json
  {
    "status": "tokens_revoked",
    "token_version": 2
  }
  ```

---

## 2. Health & Monitoring

### `GET /health` and `GET /api/health`
- **Who May Call**: Public / Unauthenticated callers.
- **Description**: Verifies database connectivity and service health.
- **Response** (`200 OK`):
  ```json
  {
    "status": "ok",
    "db": true,
    "app": "TrustVault"
  }
  ```

---

## 3. Documents Management (`/documents` or `/api/documents`)

### `POST /documents`
- **Who May Call**: **Document Owners and Admins (`role: owner` or `role: admin`)**. (Viewers receive `403 Forbidden`).
- **Headers**: Requires `X-CSRF-Token`.
- **Request**: Multipart Form Data (`multipart/form-data`)
  - `file`: Binary file upload (max 20MB, permitted extensions: `.pdf`, `.docx`, `.xlsx`, `.png`, `.jpg`, `.txt`, `.csv`).
  - `name`: String (optional document display name; sanitized against CRLF).
  - `category`: String (optional, defaults to "General"; sanitized against CRLF).
  - `description`: String (optional notes).
- **Response** (`201 Created`):
  ```json
  {
    "id": "11111111-2222-3333-4444-555555555555",
    "owner_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "name": "Financial_Report.pdf",
    "category": "Finance",
    "description": "Quarterly audit",
    "created_at": "2026-11-08T08:00:00Z",
    "current_version_id": "22222222-3333-4444-5555-666666666666",
    "versions": [
      {
        "id": "22222222-3333-4444-5555-666666666666",
        "version_no": 1,
        "size": 1048576,
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "mime": "application/pdf",
        "created_at": "2026-11-08T08:00:00Z"
      }
    ]
  }
  ```

---

### `GET /documents`
- **Who May Call**: Any authenticated user (`owner`, `viewer`, `admin`).
- **Security Guarantee**: Results are filtered in SQL (`WHERE Document.owner_id == user.id OR Grant.user_id == user.id`). Inaccessible documents are never returned.
- **Response** (`200 OK`): List of documents the caller owns or has an active grant on. For granted documents, only the current version is visible in `versions`.

---

### `GET /documents/{id}`
- **Who May Call**:
  - **Document Owner** (sees full version history).
  - **Users with an active `read` or `edit` grant** (sees only the current version in `versions`).
  - *All unauthorized callers receive HTTP 404*.
- **Response** (`200 OK`): Detailed document metadata and visible versions.

---

### `PUT /documents/{id}`
- **Who May Call**:
  - **Document Owner**.
  - **Users with an active `edit` grant**.
  - *All unauthorized callers receive HTTP 404*.
- **Headers**: Requires `X-CSRF-Token`.
- **Request**: Multipart Form Data (`multipart/form-data`)
  - `name`: Updated title.
  - `category`: Updated category.
  - `description`: Updated description.
  - `file`: Optional new file version upload (increments `version_no` and updates `current_version_id`).
- **Response** (`200 OK`): Updated document representation.

---

### `DELETE /documents/{id}`
- **Who May Call**: **Document Owner ONLY**. (Even users with `edit` grant or admins receive HTTP 404).
- **Headers**: Requires `X-CSRF-Token`.
- **Description**: Soft-deletes document by setting `deleted_at = now()`.
- **Response** (`200 OK`):
  ```json
  {
    "status": "deleted",
    "id": "11111111-2222-3333-4444-555555555555"
  }
  ```

---

### `GET /documents/{id}/download`
- **Who May Call**:
  - **Document Owner**.
  - **Users with an active `read` or `edit` grant**.
  - **Callers presenting a valid single-use download token (`?token={token_id}`)**.
  - *All unauthorized callers receive HTTP 404*.
- **Parameters**: `token` (UUID, optional).
- **Response** (`200 OK`): Decrypted raw binary file streamed with headers:
  - `Content-Disposition: attachment; filename="..."`
  - `Content-Type: <verified mime type>`
  - `X-Content-Type-Options: nosniff`
  - `Cache-Control: no-store`

---

### `POST /documents/{id}/download-token`
- **Who May Call**:
  - **Document Owner**.
  - **Users with an active `read` or `edit` grant**.
  - *All unauthorized callers receive HTTP 404*.
- **Headers**: Requires `X-CSRF-Token`.
- **Description**: Generates a single-use, 60-second time-bounded token bound to `(user_id, doc_id)`.
- **Response** (`200 OK`):
  ```json
  {
    "token": "4fa85f64-5717-4562-b3fc-2c963f66afa6",
    "expires_at": "2026-11-08T08:01:00Z",
    "download_url": "/documents/11111111-2222-3333-4444-555555555555/download?token=4fa85f64-5717-4562-b3fc-2c963f66afa6"
  }
  ```

---

## 4. Document Sharing & Access Grants

### `POST /documents/{id}/grants`
- **Who May Call**: **Document Owner ONLY**. (All other callers receive HTTP 404).
- **Headers**: Requires `X-CSRF-Token`.
- **Request Body** (`application/json`):
  ```json
  {
    "user_email": "charlie.viewer@trustvault.local",
    "perm": "read",
    "expires_at": "2026-12-31T23:59:59Z"
  }
  ```
- **Response** (`200 OK`):
  ```json
  {
    "id": "99999999-8888-7777-6666-555555555555",
    "doc_id": "11111111-2222-3333-4444-555555555555",
    "user_id": "77777777-6666-5555-4444-333333333333",
    "user_email": "charlie.viewer@trustvault.local",
    "perm": "read",
    "granted_by": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "granted_at": "2026-11-08T08:00:00Z",
    "revoked_at": null,
    "expires_at": "2026-12-31T23:59:59Z"
  }
  ```

---

### `GET /documents/{id}/grants`
- **Who May Call**: **Document Owner ONLY**.
- **Response** (`200 OK`): List of all grants issued for the document with recipient email and revocation status.

---

### `DELETE /documents/{id}/grants/{gid}`
- **Who May Call**: **Document Owner ONLY**.
- **Headers**: Requires `X-CSRF-Token`.
- **Description**: Revokes grant by setting `revoked_at = now()` and automatically marks all unredeemed download tokens for this user and document as consumed. Access terminates immediately on the next request.
- **Response** (`200 OK`):
  ```json
  {
    "status": "revoked",
    "id": "99999999-8888-7777-6666-555555555555"
  }
  ```

---

## 5. Document Search (`/search` or `/api/search`)

### `GET /search`
- **Who May Call**: Any authenticated user (`owner`, `viewer`, `admin`).
- **Query Parameters**:
  - `name`: String (ILIKE search on document name).
  - `category`: String (ILIKE search on category).
  - `owner`: String (UUID, email, or name of document owner).
  - `start_date` / `from_date`: ISO 8601 string.
  - `end_date` / `to_date`: ISO 8601 string.
  - `date_range`: String (`YYYY-MM-DD..YYYY-MM-DD`).
- **Security Guarantee**: SQL WHERE isolation strictly enforces that search results never include inaccessible documents or leak metadata/counts.
- **Response** (`200 OK`): List of matching `DocumentOut` objects.

---

## 6. AI Sharing Assistant

### `POST /documents/{id}/suggest-access`
- **Who May Call**: **Document Owner ONLY**.
- **Headers**: Requires `X-CSRF-Token`.
- **Security Guarantee**: This endpoint **NEVER** creates grants. If `ANTHROPIC_API_KEY` is configured, only doc name, category, and description are shared with the LLM; **file contents are never read or transmitted**.
- **Response** (`200 OK`): Returns a suggestion session ID (`sid`) and list of candidate recipients with reasons.
  ```json
  {
    "sid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "suggestion_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "doc_id": "11111111-2222-3333-4444-555555555555",
    "suggestions": [
      {
        "user_id": "77777777-6666-5555-4444-333333333333",
        "email": "charlie.viewer@trustvault.local",
        "user_email": "charlie.viewer@trustvault.local",
        "name": "Charlie Kim",
        "user_name": "Charlie Kim",
        "suggested_perm": "read",
        "perm": "read",
        "reason": "Previously granted access to 3 documents in the Finance category"
      }
    ]
  }
  ```

---

### `POST /documents/{id}/suggestions/{sid}/confirm`
- **Who May Call**: **Document Owner ONLY**.
- **Headers**: Requires `X-CSRF-Token`.
- **Description**: Requires explicit confirmation from the owner. The owner can accept specific picks or reject all. Records an audit event for the owner's decision.
- **Request Body** (`application/json`):
  ```json
  {
    "action": "accepted",
    "picks": [
      {
        "user_email": "charlie.viewer@trustvault.local",
        "perm": "read",
        "expires_at": null
      }
    ]
  }
  ```
- **Response** (`200 OK`):
  ```json
  {
    "status": "confirmed",
    "decision": "accepted",
    "grants": [ ... ]
  }
  ```

---

## 7. Admin & Audit Trail (`/admin` or `/api/admin`)

### `GET /admin/audit/verify`
- **Who May Call**: **Administrator only (`role: admin`)**.
- **Description**: Walks the entire hash chain from genesis to the latest record, recalculating HMAC-SHA256 signatures (`prev_hash || canonical_json(event)`). Reports validity and identifies the exact record ID if any tampering occurred.
- **Response** (`200 OK`):
  ```json
  {
    "ok": true,
    "total": 42,
    "valid": true,
    "events_checked": 42
  }
  ```

---

### `GET /admin/audit`
- **Who May Call**: **Administrator only (`role: admin`)**.
- **Query Parameters**:
  - `actor_id`: UUID filter.
  - `doc_id`: UUID filter.
  - `action`: String filter (e.g. `doc_download`, `token_redeem`, `grant_revoke`).
  - `outcome`: String filter (`allowed` or `denied`).
  - `since` / `until`: ISO 8601 timestamps.
  - `page`: Integer (default 1).
  - `per_page`: Integer (default 50, max 500).
  - `export`: Optional; set to `csv` for direct CSV file export.
- **Response** (`200 OK`): Paginated list of audit events with HMAC signatures and hash chain continuity proofs.

---

### `GET /admin/activity`
- **Who May Call**: **Administrator only (`role: admin`)**.
- **Description**: Summarizes system-wide activity, denied attempts, top actors, top documents, and security alert detections.
- **Response** (`200 OK`): JSON summary report.

---

### `GET /admin/activity/alerts`
- **Who May Call**: **Administrator only (`role: admin`)**.
- **Description**: Returns flagged behavioral anomalies (e.g. 5+ denied attempts in 10 minutes, access immediately preceding revocation, off-hours downloads, bulk downloads).
- **Response** (`200 OK`): List of detected alert items.
