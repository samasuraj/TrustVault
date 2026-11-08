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

## 2026-11-07 (Audit Trail Hardening)
- **What I asked**: Harden the audit trail: Single audit.log_event() function used everywhere; compute hash = HMAC-SHA256(secret, prev_hash || canonical_json(event)) inside a transaction with an advisory lock so the chain is consistent. Postgres trigger raising an exception on UPDATE/DELETE/TRUNCATE of audit_events. The API's DB role has INSERT/SELECT only on that table (create a separate migration role for schema changes). GET /admin/audit/verify walks the chain and reports the first broken link. Audit denied attempts too (actor, doc, action, ip). Admin endpoints: GET /admin/audit (filter by user, doc, action, outcome, date, paginated, CSV export), GET /admin/activity (summary). "Worth noticing" alerts: many denied attempts by one user in 10 minutes, downloads at odd hours, bulk downloads, grant then immediate download by a new user, access to a doc just before the grant was revoked. Show these as flagged items. Tests: direct SQL UPDATE/DELETE fails; tampering a row is detected by verify.
- **What you produced**:
  - Implemented `backend/app/audit.py` with:
    - Single `audit.log_event()` function used across all routes, acquiring PostgreSQL session-level advisory lock (`pg_advisory_lock`) + transaction lock (`with_for_update()`) for consistent concurrent hash chaining.
    - Deterministic `compute_hash` using HMAC-SHA256 with key from `cfg.audit_hmac_key` over `prev_hash || canonical_json(event)` (RFC 8785 compliant canonical JSON serialization).
    - `verify_chain(db)` function that walks the audit chain from genesis, checks `prev_hash` linkage and HMAC verification on every row, and pinpoints the first broken link or tampering.
  - Created Alembic migration `0003_audit_hardening.py`:
    - Separate triggers blocking UPDATE or DELETE (`FOR EACH ROW`) and TRUNCATE (`FOR EACH STATEMENT`) on `audit_events`.
    - Created `vault_app` runtime role granted `SELECT, INSERT` only on `audit_events` and standard DML on other tables.
    - Created `vault_migrate` role with superuser/schema management privileges.
    - Added database indexes on `audit_events` (`actor_id`, `action`, `outcome`, composite `actor_id, ts`).
  - Implemented `backend/app/admin_router.py` mounted at `/api/admin` and `/admin`:
    - `GET /admin/audit/verify`: Admin-only chain verification reporting status, total count, or first broken row details.
    - `GET /admin/audit`: Filtered (by actor, doc, action, outcome, time range), paginated, and CSV export (`export=csv`).
    - `GET /admin/activity`: Comprehensive activity dashboard summary (totals, breakdowns by action and outcome, top actors, top docs, and flagged alerts).
    - `GET /admin/activity/alerts`: Flagged items detecting "Worth noticing" security patterns (many denials in 10m, off-hours downloads 00:00-06:00 UTC, bulk downloads >5 in 1h, grant then immediate download within 60s, access within 120s prior to grant revocation).
  - Added comprehensive test suite in `backend/tests/test_audit_hardening.py` (17 tests):
    - Direct SQL tests on live Postgres confirming UPDATE, DELETE, and TRUNCATE raise DB exceptions.
    - Tamper detection tests confirming verify detects altered hash, altered prev_hash, and mutated event attributes.
    - Unit tests for HMAC deterministic derivation and advisory locking.
    - Endpoint tests for verification, pagination, filtering, CSV streaming, admin authz enforcement, and all 5 alert detection rules.
  - Rebuilt containers and verified full test suite: 184/184 tests passed.
- **What was wrong**: TODO
- **What I did instead**: TODO

## 2026-11-08 (Search & AI Sharing Assistant)
- **What I asked**: 1. GET /search with filters name (ILIKE), owner, category, date range. Permission filtering is part of the SQL WHERE clause, so results never include docs the user cannot see. Test that search never leaks names/counts of inaccessible docs. 2. AI sharing assistant: POST /documents/{id}/suggest-access (owner only) returns suggested users with reasons. Implement deterministic heuristics (people previously granted similar-category docs, same-category history), and an optional LLM call if ANTHROPIC_API_KEY is set that sees only doc name/category/description, never file contents. The suggestion NEVER creates a grant. A separate POST /documents/{id}/suggestions/{sid}/confirm requires the owner to explicitly pick users and perms. Audit both the suggestion (with what was suggested) and the owner's decision (accepted/modified/rejected). Tests: suggest endpoint changes no grants; confirm by non-owner fails.
- **What you produced**:
  - Implemented `backend/app/search_router.py` mounted at `/search` and `/api/search` (and `/documents/search` via `backend/app/doc_router.py`):
    - Multi-filter document search supporting `name` (ILIKE case-insensitive match), `category` (ILIKE match), `owner` (email, name, or UUID), and flexible `date range` (`start_date`, `end_date`, `from_date`, `to_date`, or `date_range="YYYY-MM-DD..YYYY-MM-DD"`).
    - Strict SQL WHERE clause permission enforcement (`access_clause` checking doc ownership or active unrevoked unexpired grant) and `deleted_at IS NULL` soft-delete filtering so inaccessible documents are completely excluded at the database level and never leak names, metadata, or counts.
    - Owner sees full version history while grantees see current version only.
    - Audit logging for `doc_search` recording query filters and result count.
  - Implemented AI Sharing Assistant in `backend/app/sharing_assistant.py` and endpoints in `backend/app/doc_router.py`:
    - `POST /documents/{id}/suggest-access`: Owner-only access check via `authorize(db, user, doc_id, "share")` (non-owners receive anti-enumeration 404). Generates recommendations via deterministic heuristics (scoring previous grants in the same category, similar categories, and collaborator history) and an optional Anthropic Messages API call if `ANTHROPIC_API_KEY` is present. Strictly passes only document metadata (`name`, `category`, `description`) and candidate profiles (`email`, `name`, `role`) to the LLM—never file contents, versions, or encrypted blobs. Gracefully falls back to heuristics on API timeout or failure. The suggestion NEVER creates a grant.
    - `POST /documents/{id}/suggestions/{sid}/confirm`: Owner-only confirmation endpoint requiring explicit selection of users and permissions (`read` or `edit`). Evaluates owner decision (`accepted` if exactly matching suggestions, `modified` if custom picks/permissions, `rejected` if rejected or empty). Automatically revokes any prior active grants for chosen users and creates new grants.
    - Comprehensive audit logging recording both the suggestion (`suggest_access` with suggested users and reasons) and owner's decision (`suggest_confirm` with decision status, picked grants, and original suggestions), plus `grant_create` for each confirmed grant.
  - Created test suites in `backend/tests/test_search.py` and `backend/tests/test_sharing_assistant.py`:
    - Verified permission filtering in SQL WHERE clause prevents leaking names or counts of inaccessible docs to unauthorized users, strangers, or ungranted admins.
    - Verified ILIKE name and category matching, owner filtering, and date range bounding.
    - Verified `POST /documents/{id}/suggest-access` creates zero grants in the database.
    - Verified `POST /documents/{id}/suggest-access` and confirm by non-owner fail with 404.
    - Verified deterministic heuristics prioritize same-category and collaborator history and exclude doc owner and active grantees.
    - Verified Anthropic LLM payload contains only metadata and never file contents.
    - Verified owner decision states (`accepted`, `modified`, `rejected`) and audit trail verification.
  - Full test suite verified: 188 passed, 3 skipped.
- **What was wrong**: TODO
- **What I did instead**: TODO

## 2026-11-08 (React UI Implementation)
- **What I asked**: Build the React UI: login, document list with search filters, upload with validation errors, document detail (versions, share dialog with read/edit and expiry, revoke buttons, AI suggestions panel with accept/reject), admin dashboard (audit table with filters, chain verify button, flagged alerts, user management). Handle 401/404/422 cleanly. Never render server HTML unescaped. Use cookie auth + CSRF header. Keep it clean and simple.
- **What you produced**:
  - Implemented `frontend/src/api.js` client handling:
    - Cookie-based authentication (`tv_access`) with automatic `tv_csrf` cookie extraction and `X-CSRF-Token` header injection on all mutating requests (POST, PUT, DELETE).
    - Robust error extraction mapping 401 (session expired), 404 (access denied/anti-enumeration), 413 (max 20MB size), and 422 (FastAPI validation field details) to safe strings without raw HTML rendering.
    - Complete API methods for auth, documents, search, sharing, AI suggestions, and admin endpoints.
  - Implemented `frontend/src/components/Login.jsx`:
    - Clean login form with email/password validation, error banners, and quick-fill buttons for pre-seeded RBAC accounts (Admin, Alice Owner, Bob Owner, Charlie Viewer).
  - Implemented `frontend/src/components/Navbar.jsx`:
    - Responsive header with TrustVault branding, role pill (`admin`, `owner`, `viewer`), dynamic tab navigation, and sign-out control.
  - Implemented `frontend/src/components/DocumentList.jsx`:
    - Search filter bar supporting ILIKE document name, category, owner email/name, and date ranges.
    - Zero information leakage: inaccessible documents are never returned.
    - Document table with category badges, version count, direct decrypted file download, and owner-only deletion.
  - Implemented `frontend/src/components/UploadModal.jsx`:
    - File upload modal with client-side validation (max 20MB limit, allowed extensions allowlist, double-extension block).
    - Metadata inputs (title, category select with custom option, description) and AES-256-GCM upload.
  - Implemented `frontend/src/components/DocumentDetail.jsx`:
    - Comprehensive document inspection view: metadata header and direct file download.
    - Version history panel with version number, uploaded timestamp, size, MIME type, and SHA-256 hash preview, plus "Upload New Version" form.
    - Sharing and access grants manager (owner only): active grants table with instant revocation buttons, and grant creation form (`read`/`edit` permission and optional expiration date).
    - AI Sharing Assistant panel (owner only): generates heuristic and LLM recommendations, displays per-user reason badges, checkboxes, and permission selectors, with "Accept Selected" and "Reject All" confirmation buttons.
  - Implemented `frontend/src/components/AdminDashboard.jsx` (admin only):
    - One-click HMAC-SHA256 audit chain verification with live visual status badge (intact vs tampered).
    - Security alert cards for suspicious patterns (denial spikes, off-hours downloads, bulk downloads).
    - Filterable and paginated immutable audit log table with JSON detail viewer and CSV export.
    - User management tab: user registration form and instant session revocation controls (disable user, bump token version).
  - Implemented modern, accessible CSS styling in `frontend/src/index.css`.
  - Verified compilation and production bundle build with `npm run build` (built in 2.26s with zero errors).
- **What was wrong**: TODO
- **What I did instead**: TODO

## 2026-11-08 (Hostile Pentesting & Threat Modeling)
- **What I asked**: Act as a hostile pentester against this codebase. Write tests for 27 specific threat vectors (IDOR on every route, ID enumeration via 404 vs 403, search leakage, download-token replay/sharing across users, use after revoke, expired-grant use, JWT after disable/token_version bump, CSRF, path traversal in filename, polyglot/disguised uploads, zip bombs/oversized uploads, mass assignment, privilege escalation viewer->owner, admin reading content without grant, soft-deleted doc access, old-version access by viewers, audit tampering, audit hash-chain race, SQL injection in search, response header leaks, CORS misconfig, stack traces in errors, default seed creds in prod, rate-limit bypass via X-Forwarded-For, race condition between revoke and download, file-storage volume exposure, log injection through filenames). Fix every real hole found. Then write THREATS.md with per-threat breakdown, covering test name, and a knowingly accepted section.
- **What you produced**:
  - Audited the entire backend codebase and patched identified vulnerabilities:
    - Fixed CORS misconfiguration in `backend/app/main.py`: removed wildcard `*` with credentials, restricted to explicit trusted origins (`ALLOWED_ORIGINS`).
    - Added global exception handler in `backend/app/main.py` suppressing tracebacks on unexpected HTTP 500 errors.
    - Added security response headers middleware (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, `Content-Security-Policy: default-src 'self'`, and `Server: TrustVault`).
    - Hardened IP extraction in `backend/app/deps.py`: validated IP syntax using `ipaddress` and restricted `X-Forwarded-For` evaluation to verified loopback/trusted reverse proxies.
    - Hardened file upload validation in `backend/app/storage.py`: added OpenXML archive inspection (`[Content_Types].xml`), path traversal rejection inside archives, 50MB decompression limit, 25:1 expansion ratio limits, and HTML polyglot rejection in PDFs.
    - Added `sanitize_text` to strip CRLF / non-printable control characters from document names and categories, neutralizing log injection.
    - Bound download tokens to user identity in `backend/app/doc_router.py`: rejecting cross-user token redemption attempts with HTTP 404.
    - Blocked default credential seeding in production environments (`cfg.env == "production"`) in `backend/app/seed.py`.
  - Authored comprehensive hostile pentest test suite in `backend/tests/test_pentest_suite.py` containing 27 dedicated tests with 100% pass rate (27/27 passed).
  - Verified full test suite across the repository: 215 passed, 3 skipped.
  - Authored `THREATS.md` with detailed threat descriptions, mitigations, exact test references, and a "Knowingly Accepted" risks section covering antivirus omission, single master encryption key, password-only authentication without MFA, software HMAC key in environment, and in-memory rate limiting.
- **What was wrong**: TODO
- **What I did instead**: TODO

## 2026-11-08 (Documentation, Cloud Deployment & CI Pipeline)
- **What I asked**: Produce README.md (what it is, run with docker compose up, seed credentials for admin/owner/viewer, test command), docs/API.md (every endpoint with method, path, and exactly who may call it), docs/PERMISSIONS.md, docs/WRITEUP.md (built, not built and why, permission model in plain words, AI usage, unfinished), and a deployment guide for Render or Railway (managed Postgres, env vars, volume for encrypted files, HTTPS, change seed passwords flow). Add a CI workflow running pytest. Confirm the instructions work from a clean clone.
- **What you produced**:
  - Authored comprehensive `README.md` with platform overview, single-command `docker compose up --build` launch instructions, seed credentials table, local and container test execution commands, and documentation index.
  - Authored `docs/API.md` providing an exhaustive specification of all 21 HTTP endpoints across authentication, document management, versioning, sharing, search, AI sharing assistant, and admin/audit with exact caller permissions and payload examples.
  - Authored `docs/PERMISSIONS.md` detailing the centralized `authorize()` gateway, core security invariants (deny by default, anti-enumeration, zero permission caching, separation of duties), role hierarchy, action types, grant lifecycle, single-use download tokens, and versioning access rules.
  - Authored `docs/WRITEUP.md` reviewing architectural accomplishments, features intentionally not built and their rationales (antivirus daemon, distributed Redis, cloud KMS, HSM, MFA), plain-language permission model explanation, AI privacy boundaries, and future roadmap.
  - Authored `docs/DEPLOYMENT.md` detailing production deployments on Render and Railway, PostgreSQL configuration, persistent volume mounts for encrypted files (`/var/vault/storage`), HTTPS setup, and the secure production admin provisioning procedure.
  - Created `.github/workflows/ci.yml` running PostgreSQL 16 service, Python 3.12 pytest suite (218 tests), and Node.js 20 frontend build.
  - Updated `.env.example` with complete configuration options.
  - Verified instructions and builds: `npm run build` completed in 3.65s, full pytest suite verified (215 passed, 3 skipped).
- **What was wrong**: TODO
- **What I did instead**: TODO

## 2026-11-08 (Browser End-to-End DOM Testing & Verification)
- **What I asked**: Open the browser, check that all functionalities are working properly using real DOM inspection and interaction.
- **What you produced**:
  - Authored and executed an automated end-to-end browser test suite (`scripts/browser_test.py`) using Playwright with real Chromium DOM element interaction and assertions against the running live application at `http://localhost`.
  - Tested and verified all core user personas and interface workflows:
    - **Admin Persona (`admin@trustvault.local`)**:
      - Signed in via interactive form in the DOM.
      - Navigated to the Admin Console (`/admin`).
      - Clicked "Verify Audit Hash Chain", confirmed the cryptographic verification request (`/api/admin/audit/verify`), and asserted the visual green banner `Audit Chain Cryptographically Intact` in the DOM.
      - Navigated through "Security Alerts" and "User Management" subtabs, asserting form elements (`Register New Vault User`, instant session revocation controls).
      - Verified successful sign-out.
    - **Document Owner Persona (`alice.owner@trustvault.local`)**:
      - Signed in and verified owner navigation bar (`Upload Document` button rendered).
      - Opened the modal, uploaded `sample_board_brief.pdf` with metadata (`Legal` category, description), submitted for AES-256-GCM encryption at rest, and asserted the newly created document in the table.
      - Clicked document row to open `DocumentDetail` view, asserting `Version History` (v1 metadata and SHA-256 preview) and `Access Grants` cards.
      - Clicked `Get Recommendations` on the AI Sharing Assistant panel, asserted the rendered heuristic suggestions with user reasons (`Active member`), and clicked `Accept & Grant Selected` to record confirmed grants in the tamper-proof audit trail.
      - Tested authenticated decrypted streaming download via Playwright download event listener.
      - Tested search bar ILIKE filter with dynamic query matching the document.
      - Signed out cleanly.
    - **Viewer Persona (`charlie.viewer@trustvault.local`) & RBAC Verification**:
      - Signed in as Charlie and asserted strict UI RBAC enforcement: `Upload Document` button does **not** exist anywhere in the DOM for viewers.
      - Verified that Charlie immediately sees the newly granted document in his document table (proving grant propagation).
      - Opened the document and verified viewer restrictions (`Active Grant` badge rendered, owner-only management buttons hidden).
      - Signed out cleanly.
  - Resolved UI integration issues identified during browser testing:
    - Fixed user object unwrapping in `frontend/src/api.js` and `frontend/src/App.jsx` on `/api/auth/login`.
    - Fixed `chainResult.ok` handling in `frontend/src/components/AdminDashboard.jsx` for HMAC audit chain verification display.
    - Upgraded database advisory lock mechanism in `backend/app/audit.py` to transaction-scoped `pg_advisory_xact_lock` to prevent orphaned connection locks.
  - Captured 14 high-resolution DOM verification screenshots in `browser_screenshots/`.
- **What was wrong**: TODO
- **What I did instead**: TODO

---

## 2026-11-08 — Administrative Activity Tab for Admin Dashboard

**What you asked:** Add an "Administrative Activity" section to the Admin console that shows who logged in to the website and all changes/actions each user made.

**What I produced:**
- **Backend** (`admin_router.py`): New `GET /api/admin/user-activity` endpoint that JOINs `audit_events` with `users` to return events enriched with `actor_name`, `actor_email`, `actor_role`. Supports filters: `action`, `actor_id`, `since`, `limit`, `offset`. Returns `{total, events, since}`.
- **API** (`api.js`): Added `adminApi.getUserActivity(filters)` helper.
- **Frontend** (`AdminDashboard.jsx`): Added 4th subtab "Administrative Activity" with two views:
  - **Login History**: filterable table of `auth_login` events showing user name, role, email, outcome (Success/Failed), IP, timestamp.
  - **All Activity**: full action log with action dropdown filter, actor UUID filter, date picker, colour-coded action badges per category (auth/doc/grant/suggest/admin), role badges (admin=yellow, owner=blue, viewer=grey), and pagination.
- **CSS** (`index.css`): Added `.role-badge`, `.action-{prefix}` colour variants, `.admin-activity-container`, `.activity-mode-toggle`.
- **Tests** (`test_audit_hardening.py`): Added unit tests `test_user_activity_returns_enriched_events` and `test_user_activity_filters` (220/220 backend pytest tests passing).
- **DOM Verification** (`browser_test.py`): Verified all DOM interactions in real headless Chromium: subtab switching, All User Actions table, and Login History view; captured screenshots `05b_admin_activity_all.png` and `05c_admin_activity_logins.png`.

**What was wrong:** TODO

**What I did instead:** TODO

