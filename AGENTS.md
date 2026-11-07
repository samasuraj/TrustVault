# AGENTS.md

## Project Overview
- **Project**: TrustVault, a secure document sharing platform with a provable audit trail.
- **Stack**: FastAPI (Python 3.12), PostgreSQL 16, SQLAlchemy 2 + Alembic, React + Vite, Docker Compose, pytest.

## Security Rules (Non-Negotiable)
1. Every route touching a document MUST call `authorize(user, doc_id, action)` from `app/authz.py`. No inline permission checks anywhere else.
2. Deny by default. Unauthorized access to an existing doc returns 404 (not 403) so existence is not leaked.
3. Every decision (allowed AND denied) writes an audit event.
4. Files are never served statically. Stored under random UUID names outside any web root, encrypted at rest, streamed only through an authenticated endpoint.
5. Revoking access takes effect on the next request. No cached permissions, no long-lived download links.
6. Audit table is append-only (DB trigger blocks UPDATE/DELETE) and hash-chained.
7. Never trust client input: validate type, size, filename, IDs.
8. Any change to authz or audit code must come with a test.

## Development Style
- Short variable names
- Minimal comments
- Handle errors explicitly
- Small commits with clear messages

## Process
After each task, append a draft entry to `PROMPTS.md` (date, what I asked, what you produced) and leave "What was wrong" and "What I did instead" as TODO for me to fill honestly.
