# Prompt Log

## 2026-11-07
- **What I asked**: Create AGENTS.md in the repo root with these standing rules, and follow them in every task.
- **What you produced**: Initialized the git repository, created `AGENTS.md` with project specifications, non-negotiable security rules, development style guidelines, and post-task logging procedure, and initialized `PROMPTS.md` with this draft entry.
- **What was wrong**: TODO
- **What I did instead**: TODO

## 2026-11-07 (Scaffolding)
- **What I asked**: Scaffold the project per AGENTS.md (/backend FastAPI, /frontend React+Vite, docker-compose.yml with db, api, web services, .env.example, Alembic migration + db/schema.sql with all specified tables, search indexes, health endpoint, config via env, one command to run: docker compose up --build, verify boot from clean clone).
- **What you produced**:
  - `backend/` with FastAPI (Python 3.12), SQLAlchemy 2 models, `app/authz.py` (`authorize` and `record_audit`), `app/main.py` (`/health` and `/api/health`), Alembic configuration + `migrations/versions/0001_initial_schema.py`, `backend/Dockerfile`, and pytest test suite covering authz, hash chaining, and health endpoints.
  - `db/schema.sql` with all required tables (`users`, `documents`, `doc_versions`, `grants`, `audit_events`, `download_tokens`), search indexes (`name`, `category`, `created_at`, `owner_id`), and append-only trigger blocking UPDATE/DELETE on `audit_events`.
  - `frontend/` with React + Vite, Nginx reverse proxy routing `/api/` to `api:8000`, system health dashboard, and multi-stage `frontend/Dockerfile`.
  - `docker-compose.yml` orchestrating `db` (PostgreSQL 16), `api`, and `web`, plus `.env.example` and `.gitignore`.
  - Tested and verified: booted with `docker compose up --build -d`, tested `/health` and `/api/health`, verified database schema and search indexes, verified append-only trigger rejecting mutations, and ran all unit tests via pytest (9/9 passed).
- **What was wrong**: TODO
- **What I did instead**: TODO

## 2026-11-07 (Authentication & RBAC)
- **What I asked**: Implement authentication (admin-only registration, seed script for 1 admin, 2 owners, 2 viewers with documented passwords, login with argon2 hashing, 15-min JWT in httpOnly SameSite=Strict cookie, CSRF token header for state-changing requests, per-request DB user verification for token_version and active status, brute-force lockout after 5 fails and rate limiting on /login, role definitions with admin unable to read file contents without grant, role matrix in docs/ROLES.md, audit logging for login success/failure, pytest tests for login, lockout, disabled-user token rejection).
- **What you produced**:
  - Implemented Argon2 password hashing, 15-minute JWT access tokens (`tv_access` cookie with httpOnly, SameSite=Strict), and CSRF token generator (`tv_csrf` cookie + `X-CSRF-Token` header) in `backend/app/security.py`.
  - Added request dependencies in `backend/app/deps.py` that query user on every request, enforce active status (`is_active`), verify `token_version` matches (instant revocation upon token bump or account disable), and enforce sliding window rate limiting on `/login`.
  - Implemented auth endpoints in `backend/app/auth_router.py` (`POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`, admin-only `POST /api/auth/register`, `POST /api/auth/users/{id}/disable`, and `POST /api/auth/users/{id}/bump-version`).
  - Updated `backend/app/authz.py` to enforce that admins CANNOT read/edit file contents without an explicit grant or doc ownership, preserving separation of duties.
  - Added `is_active` boolean column via migration `backend/migrations/versions/0002_add_user_is_active.py` and updated `backend/app/models.py` and `db/schema.sql`.
  - Created idempotent seed script `backend/app/seed.py` (integrated into container `entrypoint.sh`), creating 1 admin, 2 owners, and 2 viewers.
  - Authored `docs/ROLES.md` containing the RBAC capability matrix, security principles, and documented credentials for seeded accounts.
  - Added test suite in `backend/tests/test_auth.py` and updated `backend/tests/test_authz.py` covering login success, invalid password, 5-fail account lockout, disabled-user rejection, token-version revocation, rate limiting, and CSRF enforcement (20/20 tests passing).
  - Verified live login and hash-chained audit logging in PostgreSQL.
- **What was wrong**: TODO
- **What I did instead**: TODO

## 2026-11-07 (Authorization Engine & Matrix Tests)
- **What I asked**: Create app/authz.py with ONE function authorize(db, user, doc_id, action) where action in {read, download, edit, delete, share, view_meta}. Rules: doc owner = all actions. Active grant (not revoked, not expired) with perm read = read/download/view_meta; edit = those plus edit. Only owner may share/delete. Admin gets NO content access by default. Soft-deleted docs are inaccessible except to owner for restore. Return the doc if allowed, else raise NotFound after writing a 'denied' audit event. Implement it as a FastAPI dependency so no route can forget it. Query the DB every call, no caching. Write tests/test_authz_matrix.py: a parametrized matrix of every role x every action x (owner, granted-read, granted-edit, revoked, expired, stranger, admin), plus IDOR tests (swap doc IDs in every endpoint), plus a test that removing the authorize call from download makes a test fail.
- **What you produced**:
  - Implemented `authorize(db, user, doc_id, action)` in `backend/app/authz.py` with strict permission checks, query-every-call fresh DB lookups, soft-delete isolation (inaccessible except owner restore), owner-only actions (`share`, `delete`), grant enforcement (`read`: read/download/view_meta; `edit`: read/download/view_meta/edit), zero default access for admins, and anti-enumeration 404 responses with hash-chained audit logging on every outcome.
  - Implemented `RequireDocAccess` FastAPI dependency in `backend/app/authz.py` for route injection.
  - Created `backend/tests/test_authz_matrix.py` containing:
    - 126 parametrized matrix test cases across all roles (admin, owner, viewer) x actions (read, download, edit, delete, share, view_meta) x contexts (owner, granted-read, granted-edit, revoked, expired, stranger, admin).
    - Soft-deleted document protection and owner-restore tests.
    - IDOR tests verifying swapped doc IDs across GET, download, PUT, DELETE, and POST share endpoints return 404 without leaking info.
    - Test verifying that omitting `authorize()` in a download route fails security assertion.
  - Executed full test suite via pytest inside Docker container: 149 passed out of 149 tests.
- **What was wrong**: TODO
- **What I did instead**: TODO

## 2026-11-07 (Document Endpoints & Encrypted Storage)
- **What I asked**: Implement document endpoints (POST /documents multipart upload, GET /documents list ONLY docs owned/granted with SQL filter, GET /documents/{id}, PUT /documents/{id} rename/category/new version, DELETE soft delete owner, upload validation max 20MB, allowlist pdf/docx/xlsx/png/jpg/txt/csv, magic bytes match, sanitize filename, reject double extensions and executables, sha256, store random UUID, encrypt AES-256-GCM in volume, download via authorize streaming attachment with nosniff and no-store, versioning with old versions only visible to owner, audit logging, tests for stranger 404, path traversal neutralized, fake extensions rejected).
- **What you produced**:
  - Implemented `backend/app/storage.py` providing filename sanitization (stripping paths, null bytes, unicode RTL override tricks), rejection of double extensions and executables, strict magic byte verification for allowed extensions (PDF, DOCX, XLSX, PNG, JPG, TXT, CSV), 20MB size limit check, SHA-256 digest computation, and AES-256-GCM encryption at rest with per-file 12-byte cryptographic nonces stored under random UUIDs in the Docker storage volume.
  - Implemented `backend/app/doc_router.py` mounted at `/api/documents` and `/documents` covering:
    - `POST /documents`: Multipart upload, AES-256-GCM encryption, version 1 creation, and `doc_upload` audit logging.
    - `GET /documents`: Lists only documents the user owns or has an active grant on, filtered purely in SQL with `deleted_at IS NULL`.
    - `GET /documents/{id}`: Detailed view with version history where old versions are visible only to the owner (granted viewers see only the current version).
    - `PUT /documents/{id}`: Authorized metadata update and optional file version upload, creating new `DocVersion` with incremented `version_no`.
    - `DELETE /documents/{id}`: Soft delete setting `deleted_at = now()`, owner only.
    - `GET /documents/{id}/download`: Enforced via `authorize(..., 'download')`, decrypts from volume, streams with `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, and `Cache-Control: no-store`.
  - Added `backend/tests/test_documents.py` covering path traversal neutralization, unicode trick removal, executable and double-extension rejection, magic byte enforcement, AES-256-GCM encryption verification, stranger 404 rejection on all document endpoints, download headers verification, and version access control.
- **What was wrong**: TODO
- **What I did instead**: TODO

## 2026-11-07 (Document Sharing & Single-Use Download Tokens)
- **What I asked**: Implement sharing: POST /documents/{id}/grants (owner only; user email, perm read|edit, optional expiry), DELETE /documents/{id}/grants/{gid} (revoke), GET grants list. Revocation sets revoked_at; since authorize() hits the DB every call, access dies on the next request. Download links: POST /documents/{id}/download-token issues a single-use 60-second token bound to (user, doc); redeeming it re-runs authorize() at redemption time, so a revoked user's earlier tokens fail. Revoking also invalidates all unredeemed tokens for that user+doc. Audit every grant/revoke/expiry with who and when. Tests: grant, download works, revoke, same session and old token immediately fail; expired grant fails; viewer cannot grant; owner A cannot touch owner B's docs.
- **What you produced**:
  - Implemented grant management in `backend/app/doc_router.py`:
    - `POST /documents/{id}/grants`: Owner-only grant creation with recipient user email lookup, permission validation (`read` or `edit`), optional `expires_at`, revocation of any prior active grants for that user+doc, and `grant_create` audit logging.
    - `DELETE /documents/{id}/grants/{gid}`: Revokes grant by setting `revoked_at = now()`, immediately invalidates all unredeemed download tokens for `(doc_id, user_id)`, and logs `grant_revoke` audit event.
    - `GET /documents/{id}/grants`: Owner-only endpoint listing all grants with recipient emails, sorted by grant date, and logs `grants_list` audit event.
  - Implemented single-use 60-second download tokens:
    - `POST /documents/{id}/download-token`: Issues a short-lived (60s) single-use token bound to `(user, doc)` and records `token_issue` audit event.
    - Updated `GET /documents/{id}/download` to support `?token=` parameter. At redemption time, validates token existence, single-use (`used_at IS NULL`), and unexpired (`expires_at > now`), looks up the bound user, re-executes `authorize(db, bound_user, doc_id, 'download')` against live DB state, marks token used, and logs `token_redeem` audit event.
  - Updated `backend/app/authz.py` audit logging to differentiate between expired and revoked grants when logging denied access.
  - Added `get_optional_current_user` in `backend/app/deps.py` allowing token-based download requests to execute without required cookies.
  - Added comprehensive test suite in `backend/tests/test_sharing.py` covering:
    - Grant creation, authorized viewer download, token generation, single-use redemption, second-use rejection (404), revocation immediately terminating session download and pre-issued tokens (404).
    - Expired grant denial on metadata and download (404).
    - Viewer grant/revoke rejection (404 deny-by-default anti-enumeration).
    - Owner isolation (Owner A cannot view grants, grant, issue tokens, or download Owner B's doc).
    - Input validation (invalid permission 400, missing email 404, non-existent grant revoke 404).
    - Expired download token rejection (404).
    - Audit log verification for `grant_create`, `token_issue`, `token_redeem`, `grant_revoke`.
  - Full test suite verified in Docker container: 163 passed out of 163 tests.
- **What was wrong**: TODO
- **What I did instead**: TODO
