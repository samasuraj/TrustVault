# TrustVault

**TrustVault** is a secure document sharing platform with a cryptographically provable, append-only audit trail. It enforces zero-knowledge anti-enumeration, strict least-privilege role-based access control, client-isolated searches, AES-256-GCM encrypted storage at rest (PostgreSQL `bytea`), and an HMAC-SHA256 hash-chained audit ledger.

---

## Live Production Deployment

- **Web Application**: [https://trustvault-frontend-seven.vercel.app](https://trustvault-frontend-seven.vercel.app)
- **API Health**: [https://trustvault-frontend-seven.vercel.app/api/health](https://trustvault-frontend-seven.vercel.app/api/health)

### Live Demo Accounts

| Role | Email | Password | Primary Capabilities |
|---|---|---|---|
| **Admin** | `admin@trustvault.io` | `AdminVaultPass2026!` | Audit trail review, HMAC chain verification, user registration & session revocation. *(Zero file content access without grant)* |
| **Owner** | `alice.owner@trustvault.io` | `AliceVaultPass2026!` | Upload documents, manage versions, issue/revoke access grants, AI sharing assistant. |
| **Viewer** | `charlie.viewer@trustvault.io` | `CharlieVaultPass2026!` | Read metadata and download decrypted file contents for granted documents. |

---

## Quick Start (Run with Docker Compose)

The entire platform—including PostgreSQL 16 database, FastAPI backend, and React/Nginx frontend—can be launched with a single command from a clean clone:

```bash
# 1. Clone repository & navigate to folder
git clone https://github.com/your-org/trustvault.git
cd trustvault

# 2. Copy environment file (defaults configured for local development)
cp .env.example .env

# 3. Boot all services with Docker Compose
docker compose up --build
```

Once running:
- **Web Application**: Open [http://localhost](http://localhost) (or [http://localhost:80](http://localhost:80)) in your browser.
- **Backend API**: Accessible at [http://localhost:8000](http://localhost:8000) (Health check: [http://localhost:8000/health](http://localhost:8000/health)).

---

## Seed Accounts & Default Credentials

In development mode, TrustVault automatically provisions test accounts across all roles:

| Role | Name | Email | Password | Primary Capabilities |
|---|---|---|---|---|
| **Admin** | System Administrator | `admin@trustvault.local` | `AdminPassword123!` | Audit trail review, chain verification, user registration & session revocation. *(Zero file content access without grant)* |
| **Owner** | Alice Vance | `alice.owner@trustvault.local` | `AlicePassword123!` | Upload documents, manage versions, issue/revoke access grants, AI sharing assistant. |
| **Owner** | Bob Martinez | `bob.owner@trustvault.local` | `BobPassword123!` | Secondary document owner for multi-tenant isolation testing. |
| **Viewer** | Charlie Kim | `charlie.viewer@trustvault.local` | `CharliePassword123!` | Read metadata and download file contents for granted documents. |
| **Viewer** | David Chen | `david.viewer@trustvault.local` | `DavidPassword123!` | Secondary viewer for permission testing. |

> [!NOTE]
> In production environments (`ENV=production`), default seed credentials are automatically blocked and aborted by `app/seed.py`. See the [Deployment Guide](docs/DEPLOYMENT.md) for initial administrator setup.

---

## Running the Automated Test Suite

TrustVault comes with an extensive automated test suite (218 test cases) covering authorization matrices, cryptographic storage, hash-chain integrity, and a 27-threat hostile pentest suite.

### Running in Docker
```bash
docker compose exec api python -m pytest backend/tests -v
```

### Running Locally with Python
```bash
# Install backend dependencies
cd backend
pip install -r requirements.txt
pip install pytest httpx

# Run tests
python -m pytest tests -v
```

### Running Frontend Tests & Build
```bash
cd frontend
npm install
npm run build
```

---

## Architecture & Security Highlights

1. **Centralized Authorization Gateway**: Every route touching a document calls `authorize(db, user, doc_id, action)`. No inline permission checks exist anywhere else.
2. **Deny-by-Default & Anti-Enumeration**: Unauthorized requests to existing documents return **HTTP 404** (never 403), preventing attackers from enumerating valid document IDs.
3. **Zero Permission Caching**: Grants are queried live on every single request. Revocation takes effect immediately on the next request.
4. **AES-256-GCM Encrypted Storage**: Files are encrypted with per-file 12-byte random initialization vectors and stored under random UUID names outside any web root. Files are never served statically.
5. **Append-Only, Hash-Chained Audit Trail**: Audit events are cryptographically linked using HMAC-SHA256 (`prev_hash || canonical_json(event)`). A PostgreSQL database trigger prevents `UPDATE`, `DELETE`, or `TRUNCATE` operations on audit rows.
6. **Separation of Duties**: System administrators have zero implicit access to view, download, or edit document contents without an explicit grant from the document owner.
7. **AI Privacy Safeguards**: The AI sharing assistant evaluates only document titles, categories, and descriptions. **File contents are never sent to or inspected by AI**. AI suggestions never create grants without explicit human confirmation.

---

## Documentation Links

- [docs/API.md](docs/API.md): Complete API reference detailing every endpoint, method, payload, and authorized roles.
- [docs/PERMISSIONS.md](docs/PERMISSIONS.md): Deep-dive into TrustVault's authorization model, grant lifecycles, and security invariants.
- [docs/WRITEUP.md](docs/WRITEUP.md): Architectural writeup detailing built vs omitted features, permission models in plain words, AI privacy, and roadmap.
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md): Production deployment guide for Render and Railway with managed PostgreSQL, persistent volumes, and secret management.
- [THREATS.md](THREATS.md): Full hostile penetration testing report covering verified defenses and automated tests for 27 threat vectors.
