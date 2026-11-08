# TrustVault Engineering Writeup

This document outlines the architecture, implementation choices, security decisions, and roadmap for TrustVault.

---

## 1. What Was Built

### Core Backend & Security Infrastructure
- **FastAPI (Python 3.12) Core**: Asynchronous API engine structured with Pydantic v2 schemas and strict request validation.
- **Centralized Authorization Engine (`app/authz.py`)**: Unified `authorize()` function enforcing deny-by-default, zero-knowledge anti-enumeration (404 instead of 403 on ungranted documents), and live per-request database validation without caching.
- **Cryptographic Storage Engine (`app/storage.py`)**:
  - AES-256-GCM authenticated encryption at rest with unique 12-byte cryptographic initialization vectors for every version.
  - Files stored under random UUIDs outside web roots; zero static file serving.
  - Strict input sanitization: magic-byte validation, extension allowlists, executable/double-extension blocking, OpenXML archive traversal & zip bomb protection (25:1 expansion ratio / 50MB limits), and CRLF stripping to prevent log injection.
- **Append-Only, Hash-Chained Audit Trail (`app/audit.py`)**:
  - RFC 8785 canonical JSON formatting.
  - Sequential HMAC-SHA256 hash chaining (`prev_hash || canonical_json(event)`).
  - PostgreSQL concurrency locking with advisory locks (`pg_advisory_lock`) and row-level locks (`with_for_update()`).
  - Database-level trigger blocking `UPDATE`, `DELETE`, and `TRUNCATE` operations on `audit_events`.
  - One-click verification engine (`verify_chain`) that walks the audit log and detects any row modification or broken link.
- **Authentication & RBAC (`app/auth_router.py`, `app/security.py`)**:
  - Argon2id password hashing.
  - 15-minute JWTs stored in HTTP-only, `SameSite=Strict` cookies.
  - Double-submit CSRF cookie & header validation (`X-CSRF-Token`).
  - Per-request database validation of user status (`is_active`) and session version (`token_version`), enabling immediate revocation across all user sessions.
  - Brute-force account lockouts (5 failed attempts within 15 minutes) and sliding-window rate limiting.
- **Document Management & Sharing (`app/doc_router.py`)**:
  - Multi-version document history where older versions remain strictly hidden from viewers.
  - Time-bounded, granular access grants (`read` vs `edit`).
  - Single-use, 60-second download tokens dynamically re-authorized at redemption time.
  - Soft deletion with owner-only restore capability.
- **Search Engine with SQL Isolation (`app/search_router.py`)**:
  - Multi-field search (ILIKE on document name, category, owner name/email, and date ranges).
  - Permission filtering embedded directly into the SQL `WHERE` clause, preventing inaccessible document metadata or counts from leaking.
- **AI Sharing Assistant (`app/sharing_assistant.py`)**:
  - Deterministic heuristics analyzing sharing history across similar categories.
  - Optional Anthropic Claude API integration for contextual access recommendations.
  - Strict privacy boundary: **AI never sees or processes file contents**.
  - Non-granting suggestion model requiring explicit owner confirmation.
  - Full audit trail logging suggestions and owner decisions.

### Frontend User Interface
- **Modern React (Vite) Single Page Application**:
  - Responsive, accessible dashboard built with Vanilla CSS variables and clear visual hierarchy.
  - Secure API client (`api.js`) automatically injecting CSRF headers and handling 401/404/413/422 errors gracefully without unescaped HTML rendering.
  - Quick-switch login modal supporting pre-seeded test accounts.
  - Document list with live search filters, version counts, and instant download/delete triggers.
  - Comprehensive document detail view featuring version history, grant management, and the AI suggestions panel.
  - Full administrator dashboard featuring live HMAC audit chain verification, suspicious activity alerts, filterable audit event logs with CSV export, and user management controls.

### Automated Testing & CI
- **218 Pytest Tests**:
  - 126-test authorization matrix covering all roles × actions × permission states.
  - Dedicated 27-test hostile penetration testing suite covering all known attack vectors.
  - GitHub Actions CI pipeline executing automated tests and frontend build on every pull request.

---

## 2. What Was NOT Built and Why

1. **In-Line Antivirus Daemon (e.g. ClamAV)**:
   - *Why*: Integrating a real-time ClamAV container or virus scanning daemon introduces heavy binary dependencies (frequent virus definition downloads, 1GB+ memory overhead per worker). Because TrustVault encrypts files at rest and streams downloads strictly as inert attachments without server-side execution, running a heavyweight antivirus daemon was omitted for local Docker Compose simplicity.
2. **Distributed Redis Rate Limiter**:
   - *Why*: The current sliding-window rate limiter runs in-memory within the FastAPI application process. Introducing Redis would require an additional infrastructure container and connection pooling. For single-container deployments, in-memory rate limiting provides adequate brute-force protection.
3. **Envelope Encryption with Cloud KMS (AWS KMS / GCP KMS / HashiCorp Vault)**:
   - *Why*: To remain cloud-agnostic and fully functional on air-gapped or bare-metal environments, TrustVault uses a local 256-bit symmetric key (`ENCRYPTION_KEY`) for AES-256-GCM. Cloud-managed Key Encryption Keys (KEK) and Data Encryption Keys (DEK) were deferred to avoid cloud provider vendor lock-in.
4. **Hardware Security Module (HSM) for Audit HMAC Secret**:
   - *Why*: In enterprise compliance environments, audit HMAC keys reside in FIPS 140-2 Level 3 hardware appliances. Storing the HMAC secret in an environment variable is appropriate for containerized development and self-hosted deployments.
5. **Multi-Factor Authentication (MFA / TOTP / WebAuthn)**:
   - *Why*: The MVP scope prioritized robust password hashing (Argon2id), session management, account lockout, and token versioning. Adding TOTP enrollment and SMS/FIDO2 flows was deferred to subsequent milestones.

---

## 3. The Permission Model in Plain Words

TrustVault’s permission model can be understood through three simple everyday rules:

1. **"The Owner is the Boss"**:
   When you upload a document, you own it. Only you can delete it, change who can see it, view past draft versions, or ask the AI assistant for sharing advice.
2. **"Strangers See Nothing (Not Even a Locked Door)"**:
   If someone tries to access a document they don’t own and haven’t been granted access to, TrustVault doesn’t say *"Permission Denied"* (which would confirm the document exists). It says *"Document not found"*. If you don't have access, the document effectively does not exist for you.
3. **"Admins Mind the Shop, Not Your Files"**:
   System administrators have the power to create users, disable accounts, and check the audit logs to make sure nobody is tampering with the system. But they cannot peek inside your documents or download your files unless you explicitly share them with the admin, just like any other user.

---

## 4. AI Usage & Privacy Safeguards

The **AI Sharing Assistant** helps document owners determine who in their organization might need access to a newly created file. It operates under strict privacy and governance guarantees:

- **Zero Content Inspection**: The AI model **NEVER** receives, reads, parses, or stores file contents. Only high-level metadata (document title, category, and owner description) is evaluated.
- **Deterministic First, LLM Second**: TrustVault first analyzes historical sharing patterns deterministically (e.g., users frequently granted access to similar categories). An external LLM (Anthropic Claude) is only contacted if `ANTHROPIC_API_KEY` is configured.
- **Suggestions Never Grant Access**: The suggestion endpoint (`POST /documents/{id}/suggest-access`) is purely advisory and creates zero grants in the database.
- **Explicit Human Confirmation**: Grants are only created when the owner explicitly selects recipients and clicks confirm (`POST /documents/{id}/suggestions/{sid}/confirm`).
- **Complete Audit Trail**: Both the suggestion output and the owner's confirmation decision (accepted, modified, or rejected) are recorded in the tamper-evident audit log.

---

## 5. Unfinished Work & Future Roadmap

- **Multi-Factor Authentication (MFA)**: Implementing TOTP (RFC 6238) and WebAuthn hardware security keys.
- **Cloud KMS Envelope Encryption**: Adding pluggable drivers for AWS KMS, Google Cloud KMS, and HashiCorp Vault.
- **Granular Group Management**: Enabling owners to grant access to departments or teams rather than individual email addresses.
- **Watermarking Engine**: Dynamically burning user email and download timestamp into PDF pages upon download to deter physical screen capture leaks.
- **Webhook Alerts**: Pushing security alerts (e.g., audit tampering detected, brute-force lockout triggered) to Slack, PagerDuty, or enterprise SIEM platforms.
