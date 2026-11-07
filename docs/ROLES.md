# TrustVault Role-Based Access Control (RBAC)

TrustVault implements a strict principle of least privilege and zero-knowledge data separation.

## Role Permission Matrix

| Capability / Action | `admin` | `owner` | `viewer` | Notes |
| :--- | :---: | :---: | :---: | :--- |
| **User Management** (Register, Disable, Bump Token) | ✅ | ❌ | ❌ | Admin only |
| **System Audit Log Review** (Inspect audit_events) | ✅ | ❌ | ❌ | Metadata & integrity checks |
| **Upload Documents** | ❌ | ✅ | ❌ | Owners create documents |
| **Manage Own Documents** (Update metadata, upload version) | ❌ | ✅ | ❌ | Owner only |
| **Grant / Revoke Permissions** on Documents | ❌ | ✅ | ❌ | Document owners manage grants |
| **Read Document Content / Download File** | ⚠️ *Grant Required* | ✅ (Own) / ⚠️ *Grant Required* | ⚠️ *Grant Required* | **Strict Security Rule:** Admin CANNOT read or download file contents without an explicit grant |
| **Edit Document Content** | ⚠️ *Grant Required* | ✅ (Own) / ⚠️ *Grant Required* | ⚠️ *Grant Required* | Only owners or users with `edit` grant |

### Key Security Principles
1. **Separation of Duties & Zero-Backdoor**: System administrators can inspect audit trails, manage user provisioning, and monitor health, but have **NO inherent privilege** to view or download sensitive document content. To access a document, an admin must be granted access by the owner like any other user.
2. **Deny by Default & Anti-Enumeration**: If a user (including an admin without grant) attempts to access a document they do not own and have no active grant for, the system returns `404 Not Found` (never `403 Forbidden`).
3. **Instant Revocation**: Modifying user active status (`is_active = False`) or bumping `token_version` invalidates all issued JWTs on their next request. Document grant revocation takes effect immediately.

---

## Seed Accounts

The system includes pre-seeded accounts created by `python -m app.seed`:

| Role | Name | Email | Password | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **admin** | System Administrator | `admin@trustvault.local` | `AdminPassword123!` | User provisioning & audit review |
| **owner** | Alice Vance | `alice.owner@trustvault.local` | `AlicePassword123!` | Document creation & grant management |
| **owner** | Bob Martinez | `bob.owner@trustvault.local` | `BobPassword123!` | Secondary document owner |
| **viewer** | Charlie Kim | `charlie.viewer@trustvault.local` | `CharliePassword123!` | Read/edit document consumer |
| **viewer** | David Chen | `david.viewer@trustvault.local` | `DavidPassword123!` | External viewer |
