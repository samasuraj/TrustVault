# TrustVault Permission & Authorization Model

This document provides an in-depth explanation of TrustVault's authorization engine, permission lifecycle, security invariants, and role hierarchy.

---

## 1. Core Authorization Invariants

TrustVault is engineered around five non-negotiable security principles:

1. **Centralized Authorization Gateway**:
   Every route touching a document MUST invoke `authorize(db, user, doc_id, action)` from `app/authz.py`. No inline or route-level permission checks are permitted anywhere else in the codebase.
2. **Deny by Default & Anti-Enumeration**:
   Unauthorized access to an existing document returns **HTTP 404 Not Found** (never 403 Forbidden). Attackers cannot probe UUIDs to determine which documents exist on the system.
3. **Zero Permission Caching**:
   Authorization queries live PostgreSQL records on every single HTTP request. When an owner revokes access or a grant expires, access terminates on the very next request without waiting for cache timeouts.
4. **Separation of Duties (Zero Admin Backdoor)**:
   System administrators have zero inherent privilege to view, download, or edit document contents. An admin attempting to read an ungranted document receives HTTP 404 like any other unauthorized user.
5. **Universal Audit Trail**:
   Every authorization evaluation—both allowed and denied—is logged to an append-only, HMAC-SHA256 hash-chained audit table.

---

## 2. Roles & Capabilities

TrustVault implements three primary roles defined at the user level:

| Role | Description | Allowed Actions |
|---|---|---|
| `admin` | System Administrator | User management (`register`, `disable`, `bump-version`), audit inspection, chain verification, activity monitoring. **Cannot read or download document contents without an explicit grant.** |
| `owner` | Document Owner | File upload, document management, grant issuance, grant revocation, download token generation, document deletion, AI sharing suggestions. |
| `viewer` | Document Consumer | Read metadata and download file contents for documents they have been granted access to. May edit documents if granted the `edit` permission. **Cannot upload new documents or issue grants.** |

---

## 3. Supported Actions

The authorization gateway evaluates seven atomic document actions:

| Action | Meaning | Allowed Actors |
|---|---|---|
| `read` | Retrieve document metadata (`GET /documents/{id}`) | Document Owner OR Active Grantee (`read` or `edit` perm) |
| `download` | Stream decrypted binary file (`GET /documents/{id}/download`) | Document Owner OR Active Grantee (`read` or `edit` perm) OR Valid Download Token |
| `view_meta` | List document in search/overview tables | Document Owner OR Active Grantee (`read` or `edit` perm) |
| `edit` | Update metadata or upload new file version (`PUT /documents/{id}`) | Document Owner OR Active Grantee (`edit` perm) |
| `share` | Issue/revoke grants or view grant list | **Document Owner ONLY** |
| `delete` | Soft-delete document (`DELETE /documents/{id}`) | **Document Owner ONLY** |
| `restore` | Restore soft-deleted document | **Document Owner ONLY** |

---

## 4. Grants Lifecycle & Inheritance

Document sharing is managed through discrete, granular `Grant` records issued by document owners to recipient users identified by email.

### Permissions: `read` vs `edit`
- **`read`**: Grants permission to inspect document metadata and download decrypted file versions.
- **`edit`**: Inherits all `read` permissions and additionally permits modifying document title, category, description, and uploading new file versions.

### Expiry Timestamps (`expires_at`)
- An owner can optionally attach an `expires_at` timestamp to a grant.
- When `expires_at <= now()`, `authorize()` evaluates the grant as non-existent and returns HTTP 404.

### Revocation Semantics (`revoked_at`)
- When an owner calls `DELETE /documents/{id}/grants/{gid}`:
  1. The grant's `revoked_at` column is set to the current UTC timestamp.
  2. All unredeemed download tokens for `(doc_id, user_id)` are immediately marked as used/consumed.
  3. `authorize()` queries `Grant.revoked_at.is_(None)` on every request, so access dies instantaneously.

---

## 5. Single-Use Download Tokens

For workflows where files must be downloaded without passing session cookies (e.g. background downloaders or strict headless environments), TrustVault issues single-use tokens:

1. **Issuance**: `POST /documents/{id}/download-token` requires active authorization and creates a token bound to `(user_id, doc_id)` with a strict 60-second time-to-live (`expires_at = now() + 60s`).
2. **Redemption**: `GET /documents/{id}/download?token={token_id}` validates token presence, ensures it has not expired, and marks `used_at = now()` inside a database transaction to prevent replay attacks.
3. **Dynamic Re-Authorization**: At redemption time, the server re-runs `authorize(db, bound_user, doc_id, "download")` against live database grants. If the user's access was revoked after the token was issued, the download is rejected with HTTP 404.
4. **User Binding**: If an authenticated caller presents another user's download token, the server rejects the request with HTTP 404 (`token_user_mismatch`).

---

## 6. Document Versioning & Access Control

TrustVault supports multi-version document history with strict role-based visibility:

- **Owners**: Document owners see the entire version history (`DocVersion` records ordered by `version_no DESC`), including draft sizes, upload timestamps, and SHA-256 digests.
- **Grantees (Viewers/Editors)**: Grantees only receive information about the current active version (`current_version_id`). Historical drafts and previous version hashes are redacted to prevent information leakage.
- **File Storage**: Every version stores its ciphertext payload under a unique random UUID on an encrypted volume outside any web root. Files are never served statically.

---

## 7. Soft-Delete Semantics

When a document owner issues a `DELETE /documents/{id}` request:
- The record is soft-deleted by setting `deleted_at = now()`.
- Once soft-deleted:
  - All grantee queries (`read`, `download`, `edit`) return **HTTP 404 Not Found**.
  - Search queries exclude the document via SQL `WHERE Document.deleted_at IS NULL`.
  - The document owner receives HTTP 404 on read/download attempts unless an explicit `restore` action is triggered.
