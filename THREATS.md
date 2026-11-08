# TrustVault Threat Model & Pentest Report

This document details the hostile penetration testing evaluation, security mitigations, automated test coverage, and knowingly accepted risks for the TrustVault platform.

---

## Threat Matrix & Verified Defenses

### 1. Insecure Direct Object References (IDOR)
- **Attack**: An attacker authenticated as a regular viewer or an unrelated user attempts to directly access, download, modify, delete, share, or request AI suggestions for a document owned by another tenant by guessing or substituting UUIDs in API route parameters.
- **What Was Done**: All document operations route through a centralized authorization gateway `authorize(db, user, doc_id, action)` in `app/authz.py`. No inline permission checks exist elsewhere. Unauthorized access to any document returns HTTP 404 (never 403), ensuring document existence and metadata are never leaked.
- **Covering Test**: `test_idor_all_routes`

### 2. ID Enumeration via 404 vs 403 Timing and Error Messages
- **Attack**: An adversary probes document endpoints with brute-forced UUIDs, observing differences in HTTP status codes (403 Forbidden vs 404 Not Found), error response bodies, or database query timing to deduce valid document IDs.
- **What Was Done**: TrustVault strictly enforces "deny-by-default". Accessing an existing document without permission returns the exact same HTTP 404 status code and identical JSON payload (`{"detail": "Document not found"}`) as querying a completely non-existent UUID. Both execution paths perform database queries and record audit events to minimize timing discrepancies.
- **Covering Test**: `test_id_enumeration_timing_and_messages`

### 3. Search Metadata & Count Leakage
- **Attack**: An attacker queries `GET /search` with wildcards, common document keywords, or categories to glean confidential document titles, counts, or ownership associations for files they are not authorized to view.
- **What Was Done**: Permission isolation is pushed directly into the SQL `WHERE` clause (`Document.owner_id == user.id OR Grant.user_id == user.id`). Inaccessible records are filtered at the database engine level, ensuring unauthorized document titles and aggregate counts are never included in query results.
- **Covering Test**: `test_search_leakage_prevented`

### 4. Download Token Replay & Cross-User Sharing
- **Attack**: An attacker captures a single-use download token generated for another user and attempts to redeem it, or attempts to replay a previously consumed download token to bypass authorization checks.
- **What Was Done**: Download tokens are single-use (`used_at` timestamp marked on redemption), 60-second time-bounded, and strictly bound to `(user_id, doc_id)`. If an authenticated user presents a token issued to a different user, the redemption is rejected with 404. Any subsequent attempt to reuse a consumed token fails with 404.
- **Covering Test**: `test_download_token_replay_and_sharing_rejected`

### 5. Use After Revoke (Permission Caching Bypass)
- **Attack**: A grantee whose document access was revoked by the document owner continues accessing or downloading the document using an active browser session or cached permission state.
- **What Was Done**: TrustVault forbids permission caching. Every single request touching a document queries PostgreSQL directly for live grant records (`revoked_at IS NULL` and `expires_at > now()`). Revocation takes effect instantly on the very next HTTP request.
- **Covering Test**: `test_use_after_revoke_immediate_failure`

### 6. Expired Grant Use
- **Attack**: A user with a time-limited grant attempts to access or download document contents after the expiration timestamp has passed.
- **What Was Done**: Authorization logic compares `Grant.expires_at` against UTC `datetime.now(timezone.utc)` on every evaluation. Expired grants are evaluated as non-existent and return HTTP 404.
- **Covering Test**: `test_expired_grant_rejected`

### 7. JWT Retention After Account Disable or Token Revocation
- **Attack**: An attacker with a captured 15-minute JWT continues calling authenticated endpoints after the user account has been disabled by an administrator or after all active sessions have been invalidated.
- **What Was Done**: The `get_current_user` dependency validates every request against the live database record: verifying `user.is_active is True` and `user.token_version == payload["tv"]`. Bumping `token_version` or toggling `is_active = False` invalidates all outstanding JWTs immediately with HTTP 401.
- **Covering Test**: `test_jwt_after_disable_and_version_bump`

### 8. Cross-Site Request Forgery (CSRF)
- **Attack**: A malicious website induces a victim's browser to submit state-changing requests (document uploads, grant creation, revocations) using ambient session cookies.
- **What Was Done**: TrustVault issues an independent `tv_csrf` cookie alongside the HTTP-only `tv_access` session cookie. All state-changing methods (`POST`, `PUT`, `PATCH`, `DELETE`) require an `X-CSRF-Token` HTTP request header matching the cookie value, rejecting unauthorized forged requests with HTTP 403.
- **Covering Test**: `test_csrf_enforcement`

### 9. Path Traversal in Filenames
- **Attack**: An adversary uploads a file with relative directory traversal characters (`../../../../etc/passwd` or `..\\..\\windows\\win.ini`) to overwrite system configuration or write outside the intended storage root.
- **What Was Done**: `sanitize_filename` in `app/storage.py` normalizes unicode (NFKD), strips non-printable and directional override characters, normalizes slashes, and applies `os.path.basename` to extract strictly the final filename. Stored files are written to disk under cryptographically random UUIDs outside any web root, completely decoupling user-supplied filenames from the filesystem layout.
- **Covering Test**: `test_path_traversal_filename_neutralized`

### 10. Polyglot & Disguised Uploads
- **Attack**: An attacker uploads executable binaries or HTML/SVG scripts renamed with permitted extensions (e.g., `payload.exe` renamed to `payload.png` or `payload.pdf`) to trigger server-side execution or client-side XSS.
- **What Was Done**: `verify_file_content` in `app/storage.py` inspects magic bytes for all allowed file types (`%PDF-`, `\x89PNG\r\n\x1a\n`, `\xff\xd8\xff`, `PK\x03\x04`). PDF uploads are checked to reject disguised HTML/script polyglots, and text files are scanned to reject binary null bytes. Downloads are served with `X-Content-Type-Options: nosniff` and `Content-Disposition: attachment`.
- **Covering Test**: `test_polyglot_and_disguised_uploads_rejected`

### 11. Zip Bombs & Oversized Decompression Bombs
- **Attack**: An attacker uploads an archive-based document (`.docx` or `.xlsx`) engineered with massive compression ratios or huge uncompressed payloads to cause denial-of-service via resource exhaustion.
- **What Was Done**: File uploads are capped at 20 MB (`MAX_FILE_SIZE`). For OpenXML formats (`docx`, `xlsx`), the zip container is validated: requiring `[Content_Types].xml`, rejecting path traversal inside archive entries, enforcing a maximum uncompressed limit of 50 MB, and rejecting compression expansion ratios exceeding 25:1.
- **Covering Test**: `test_zip_bomb_and_oversized_uploads_rejected`

### 12. Mass Assignment (Role / Owner ID Tampering)
- **Attack**: An attacker injects `owner_id`, `role`, or `user_id` fields into document creation or update form payloads to transfer document ownership or escalate privileges.
- **What Was Done**: Document ownership is strictly bound to the authenticated session (`user.id` from verified JWT). Request body parameters cannot override `doc.owner_id` or `user.role`, rendering mass assignment attempts ineffective.
- **Covering Test**: `test_mass_assignment_prevented`

### 13. Privilege Escalation (Viewer to Owner)
- **Attack**: A user assigned the `viewer` role attempts to upload new documents or issue access grants to other users.
- **What Was Done**: `upload_document` enforces that only users with `owner` or `admin` roles can create documents (rejecting viewers with 403). Grant creation is restricted exclusively to the document owner via `authorize(db, user, doc_id, "share")`.
- **Covering Test**: `test_privilege_escalation_viewer_to_owner`

### 14. Admin Reading Document Content Without Grant
- **Attack**: An administrator uses administrative privileges to view confidential document metadata or download file contents without an explicit grant from the document owner.
- **What Was Done**: TrustVault strictly enforces separation of duties. Administrators have zero implicit access to document contents or downloads. `authorize()` verifies ownership or active grants regardless of whether the caller has the `admin` role. An admin attempting to read an ungranted document receives HTTP 404.
- **Covering Test**: `test_admin_reading_content_without_grant_denied`

### 15. Access to Soft-Deleted Documents
- **Attack**: An attacker attempts to read or download a document that has been marked as deleted (`deleted_at IS NOT NULL`).
- **What Was Done**: `authorize()` checks `doc.deleted_at` prior to evaluating grants. Soft-deleted documents return HTTP 404 for all actions except an explicit `restore` action executed by the original owner.
- **Covering Test**: `test_soft_deleted_doc_inaccessible`

### 16. Viewer Access to Prior Document Versions
- **Attack**: A viewer granted read access to a document attempts to retrieve older draft versions containing sensitive historical information.
- **What Was Done**: When returning document details via `GET /documents/{id}`, version history is filtered based on ownership: the document owner receives all versions, whereas grantees receive only the current active version (`doc.current_version_id`).
- **Covering Test**: `test_old_versions_hidden_from_viewers`

### 17. Database Audit Log Tampering
- **Attack**: A compromised database account or rogue insider modifies audit log actions, outcomes, or details directly in PostgreSQL to cover their tracks.
- **What Was Done**: The database enforces append-only storage through a trigger (`audit_events_immutable`) that raises an exception on `UPDATE`, `DELETE`, or `TRUNCATE`. Additionally, every audit record is cryptographically linked via HMAC-SHA256 hash chaining (`prev_hash || canonical_json(event)`). The verification endpoint `GET /admin/audit/verify` walks the chain and pinpoints the exact record ID where tampering occurred.
- **Covering Test**: `test_audit_tampering_detected`

### 18. Audit Hash-Chain Race Conditions
- **Attack**: High-concurrency operations cause interleaved audit writes, resulting in broken or branching hash chains.
- **What Was Done**: `log_event()` acquires a PostgreSQL session-level advisory lock (`pg_advisory_lock(7777777777)`) combined with a transaction-level lock (`with_for_update()`) on the latest audit event before computing the sequential HMAC-SHA256 digest, guaranteeing linear chain integrity even under high concurrent load.
- **Covering Test**: `test_audit_hash_chain_race_resilient`

### 19. SQL Injection in Document Search
- **Attack**: An attacker inputs SQL injection payloads (`' OR '1'='1`, `'; DROP TABLE documents; --`) into name, category, or owner search query parameters.
- **What Was Done**: All search queries in `app/search_router.py` utilize SQLAlchemy parameterized expressions and escaped ILIKE pattern matching. Injected control characters are treated as literal search strings, preventing query manipulation and unauthorized record disclosure.
- **Covering Test**: `test_sql_injection_search_prevented`

### 20. Sensitive Information Disclosure via HTTP Headers
- **Attack**: An attacker analyzes HTTP response headers to fingerprint server software versions or exploit missing browser security defenses (clickjacking, MIME confusion).
- **What Was Done**: Custom ASGI middleware injects hardened security headers on every response:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - `Content-Security-Policy: default-src 'self'`
  - `Server: TrustVault` (suppressing underlying Uvicorn / server stack details)
- **Covering Test**: `test_response_security_headers`

### 21. Cross-Origin Resource Sharing (CORS) Misconfiguration
- **Attack**: An attacker uses a malicious web origin to perform credentialed cross-origin requests by exploiting a wildcard `*` with `Access-Control-Allow-Credentials: true`.
- **What Was Done**: Wildcard origins are strictly prohibited. TrustVault restricts `allow_origins` to an explicit whitelist of trusted frontend origins (`http://localhost:5173`, `http://127.0.0.1:5173`, etc.), rejecting cross-origin credential sharing from untrusted origins.
- **Covering Test**: `test_cors_no_wildcard_with_credentials`

### 22. Stack Trace Leaks on Unhandled Server Exceptions (500)
- **Attack**: An attacker triggers unexpected application faults to extract stack traces, internal database paths, and sensitive variable values from error bodies.
- **What Was Done**: A global exception handler in `app/main.py` catches all unhandled exceptions, returning a clean HTTP 500 response with `{"detail": "Internal server error"}` while suppressing all internal tracebacks and exception strings.
- **Covering Test**: `test_stack_traces_suppressed_on_500`

### 23. Default Seed Credentials in Production
- **Attack**: An attacker uses publicly documented default development credentials (`AdminPassword123!`) to gain initial access to a production deployment.
- **What Was Done**: `seed_users()` in `app/seed.py` verifies the environment configuration. If `cfg.env == "production"`, execution is immediately halted with a `RuntimeError`, preventing default credentials from being seeded into production environments.
- **Covering Test**: `test_seed_creds_blocked_in_production`

### 24. Rate Limit Bypass via Spoofed X-Forwarded-For
- **Attack**: An attacker rotates arbitrary IP strings in the `X-Forwarded-For` HTTP header to bypass login brute-force limits and IP-based rate limiting.
- **What Was Done**: `get_client_ip()` in `app/deps.py` inspects the immediate network peer (`req.client.host`). `X-Forwarded-For` headers are only evaluated if the connecting peer is an explicitly trusted reverse proxy (loopback/internal proxy). Furthermore, candidate IPs are parsed and validated using Python's `ipaddress` module, preventing header injection and rate-limit partitioning.
- **Covering Test**: `test_rate_limit_spoofed_forwarded_for_handled`

### 25. Race Condition Between Grant Revocation and Token Download
- **Attack**: An attacker issues a download token, and races token redemption against an owner's revocation request.
- **What Was Done**: Revoking a grant automatically updates all pending, unredeemed download tokens for `(doc_id, user_id)` to mark them invalid. Furthermore, `download_document` dynamically invokes `authorize(db, user, doc_id, "download")` at redemption time against the live database, ensuring any grant revoked during redemption immediately returns HTTP 404.
- **Covering Test**: `test_race_condition_revoke_and_download`

### 26. Storage Volume Directory Exposure
- **Attack**: An adversary attempts to browse file storage directly through the web server or locate readable file names on the host filesystem.
- **What Was Done**: Files are stored outside any web server document root in a dedicated volume (`/var/vault/storage`). Files are never served statically. Every file is stored under a random UUID name with no readable extension, encrypted at rest with AES-256-GCM and a unique 12-byte initialization vector. Plaintext content is only accessible through authenticated, streaming endpoints.
- **Covering Test**: `test_storage_volume_not_exposed`

### 27. Log Injection via CRLF in Filenames and Metadata
- **Attack**: An attacker submits document names or filenames containing Carriage Return and Line Feed sequences (`\r\n`) to inject forged audit events or split server log streams.
- **What Was Done**: Both `sanitize_filename` and `sanitize_text` strip control characters and unicode formatting artifacts (`\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069`), replacing CRLF sequences with whitespace before logging or storing metadata.
- **Covering Test**: `test_log_injection_crlf_neutralized`

---

## Knowingly Accepted Risks

The following architectural and operational tradeoffs have been knowingly accepted for the current release:

1. **No Real-Time Antivirus / Malware Sandbox Daemon**:
   - *Reasoning*: TrustVault enforces strict magic-byte validation, file extension allowlists, OpenXML zip bomb / decompression checks, and strips HTML/script polyglots. Uploaded files are encrypted at rest and never executed on the server. However, an authorized user could upload a malicious payload (e.g. an exploit-carrying PDF) that infects another user's workstation upon download. Running an in-line ClamAV daemon or external malware sandbox was omitted to avoid heavyweight external runtime dependencies in self-contained deployments.

2. **Single Master Symmetric Key for Encryption at Rest**:
   - *Reasoning*: TrustVault encrypts all documents using AES-256-GCM with per-file 12-byte random nonces. However, all files are encrypted under a single master key (`cfg.encryption_key`). Envelope encryption (where each document has a unique Data Encryption Key encrypted under a Key Encryption Key managed by AWS KMS, GCP KMS, or Vault) was deferred to avoid requiring cloud-provider lock-in for local Docker Compose installations. Re-encrypting all files is required if the master key is rotated.

3. **Password-Only Authentication Without Multi-Factor Authentication (MFA/TOTP)**:
   - *Reasoning*: Passwords are protected using Argon2id with account lockout (5 failed attempts within a 15-minute window) and IP-based rate limiting. While secure against basic online brute force, TrustVault lacks second-factor authentication (TOTP or FIDO2/WebAuthn). Compromised user credentials could allow unauthorized access until revoked by an administrator.

4. **Software-Based HMAC Secret (No Hardware Security Module / HSM)**:
   - *Reasoning*: The audit trail uses HMAC-SHA256 with sequential hash chaining verified in PostgreSQL. The HMAC secret key (`cfg.audit_hmac_key`) is loaded from process environment variables rather than a FIPS 140-2 Level 3 Hardware Security Module (HSM). If an attacker obtains root host access or reads process memory, they could forge HMAC signatures for newly created events from that moment forward (though historical events protected by the PostgreSQL append-only trigger remain tamper-evident).

5. **In-Memory Rate Limiting**:
   - *Reasoning*: The login rate limiter utilizes an in-memory sliding window map (`_login_attempts`). When deploying TrustVault behind multiple horizontal backend replicas, rate limiting will not be globally shared across workers without a centralized cache like Redis. For multi-replica production deployments, rate limiting must be offloaded to an ingress reverse proxy (such as Nginx or Cloudflare).
