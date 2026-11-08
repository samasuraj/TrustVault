# TrustVault Cloud Deployment Guide (Render & Railway)

This guide walks through deploying TrustVault to cloud platforms like **Render** or **Railway** using managed PostgreSQL, persistent volumes for encrypted document storage, HTTPS termination, and secure production secret management.

---

## Architecture Overview

In production, TrustVault consists of:
1. **Managed PostgreSQL 16+**: Persistent relational database hosting users, grants, document metadata, and the append-only audit log.
2. **Backend API Service**: Python FastAPI application running behind Gunicorn/Uvicorn workers.
3. **Frontend Web Service**: Static React application (or reverse proxy container) served over HTTPS.
4. **Persistent Storage Volume**: Dedicated persistent disk mount attached to the backend container (e.g. at `/var/vault/storage`) where encrypted document versions reside.

---

## Option 1: Deploying to Render

### Step 1: Provision Managed PostgreSQL
1. Log into your [Render Dashboard](https://dashboard.render.com).
2. Click **New +** → **PostgreSQL**.
3. Name your database (e.g. `trustvault-db`).
4. Select PostgreSQL version `16`.
5. Note the **Internal Database URL** (e.g., `postgres://vault:password@dpg-xxxx-a.render.com/trustvault_db`).

---

### Step 2: Deploy Backend Web Service
1. In the Render Dashboard, click **New +** → **Web Service**.
2. Connect your TrustVault Git repository.
3. Configure service settings:
   - **Name**: `trustvault-api`
   - **Region**: Same region as your PostgreSQL instance.
   - **Environment**: `Docker`
   - **Dockerfile Path**: `./backend/Dockerfile`
   - **Docker Context**: `./backend`
4. Add a **Persistent Disk**:
   - In **Disks**, click **Add Disk**.
   - **Name**: `vault-storage`
   - **Mount Path**: `/var/vault/storage`
   - **Size**: 10 GB (or as required).
5. Configure **Environment Variables**:

| Variable | Value / Description |
|---|---|
| `ENV` | `production` *(Enforces security rules & disables default seed passwords)* |
| `DATABASE_URL` | Replace `postgres://` from Render with `postgresql+psycopg2://...` |
| `SECRET_KEY` | Generate with `openssl rand -hex 32` |
| `ENCRYPTION_KEY` | Generate with `openssl rand -hex 32` |
| `AUDIT_HMAC_KEY` | Generate with `openssl rand -hex 32` |
| `STORAGE_DIR` | `/var/vault/storage` |
| `ALLOWED_ORIGINS` | `https://trustvault-web.onrender.com` *(Your frontend URL)* |
| `PORT` | `8000` |

---

### Step 3: Deploy Frontend Web Service
1. Click **New +** → **Static Site**.
2. Connect your Git repository.
3. Configure build settings:
   - **Root Directory**: `frontend`
   - **Build Command**: `npm install && npm run build`
   - **Publish Directory**: `dist`
4. Add rewrite rules for client-side routing in **Redirects/Rewrites**:
   - **Source**: `/*`
   - **Destination**: `/index.html`
   - **Action**: `Rewrite`
5. Note your frontend domain: `https://trustvault-web.onrender.com`.

---

## Option 2: Deploying to Railway

### Step 1: Provision Project & Database
1. Open [Railway](https://railway.app) and create a **New Project**.
2. Click **Provision PostgreSQL**.
3. Once created, click on PostgreSQL → **Variables** and copy `DATABASE_URL`.

---

### Step 2: Deploy Backend Service
1. In your Railway project, click **New** → **GitHub Repo** and select TrustVault.
2. In **Settings** → **Service**:
   - **Root Directory**: `backend`
   - **Dockerfile Path**: `Dockerfile`
3. Add a **Volume**:
   - In the backend service, go to **Volumes** → **Add Volume**.
   - **Mount Path**: `/var/vault/storage`
4. In **Variables**, add:
   - `ENV=production`
   - `DATABASE_URL=${{Postgres.DATABASE_URL}}` (Use psycopg2 driver: `postgresql+psycopg2://...`)
   - `SECRET_KEY=<32-byte-hex-secret>`
   - `ENCRYPTION_KEY=<32-byte-hex-secret>`
   - `AUDIT_HMAC_KEY=<32-byte-hex-secret>`
   - `STORAGE_DIR=/var/vault/storage`
   - `ALLOWED_ORIGINS=https://trustvault-frontend.up.railway.app`
5. Generate a public domain under **Networking** (e.g. `https://trustvault-api.up.railway.app`).

---

### Step 3: Deploy Frontend Service
1. Click **New** → **GitHub Repo** → select TrustVault.
2. In **Settings**:
   - **Root Directory**: `frontend`
   - **Build Command**: `npm run build`
   - **Start Command**: `npm run preview -- --port $PORT --host 0.0.0.0`
3. Generate a public domain under **Networking**.

---

## Production Security: Changing Seed Passwords & Provisioning Admin

In development, `app/seed.py` creates default test accounts with documented passwords (`AdminPassword123!`).

> [!CAUTION]
> In production (`ENV=production`), `seed_users()` is **hard-coded to raise a RuntimeError and abort** to prevent default development credentials from ever existing in a production database.

### Initial Production Administrator Provisioning

To create your initial production administrator:

1. Open a remote shell or one-off task on your deployed backend container:
   - **Render**: Dashboard → `trustvault-api` → **Shell** tab.
   - **Railway**: CLI via `railway run /bin/sh` or dashboard terminal.
2. Run the secure interactive admin provisioning script:
   ```bash
   python -c "
   import getpass, uuid
   from app.db import SessionLocal
   from app.models import User
   from app.security import hash_pw

   email = input('Admin Email: ').strip().lower()
   name = input('Admin Name: ').strip()
   pw = getpass.getpass('Admin Password: ')

   db = SessionLocal()
   u = User(
       id=uuid.uuid4(),
       email=email,
       name=name,
       pw_hash=hash_pw(pw),
       role='admin',
       is_active=True,
       token_version=1,
   )
   db.add(u)
   db.commit()
   print(f'Administrator {email} created successfully!')
   "
   ```
3. Once logged in as the newly created administrator, navigate to the **Admin Dashboard** → **User Management** tab to register company document owners and viewers with strong, unique passwords.

---

## HTTPS & Cookie Security Checklist

Before directing real traffic to production, verify:
- [x] **HTTPS Enabled**: SSL certificates are automatically provisioned by Render/Railway.
- [x] **Secure Cookie Flags**: Session cookies (`tv_access`, `tv_csrf`) automatically set `Secure`, `HttpOnly`, and `SameSite=Strict`.
- [x] **Security Headers**: Verify responses include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'self'`.
- [x] **Persistent Volume Verification**: Upload a test document, restart the backend service, and verify the file remains downloadable and decryptable from the storage volume.
- [x] **Audit Integrity Check**: Navigate to `/admin/audit/verify` to confirm HMAC hash chain continuity.
