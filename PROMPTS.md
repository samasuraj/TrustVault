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



