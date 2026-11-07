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

