# AuthNex — Multi-Tenant Authentication Platform

> Cloudflare Workers + D1 + KV · TypeScript · Zero Infrastructure · Edge-First

---

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [File Structure](#file-structure)
- [Database Schema](#database-schema)
- [API Reference](#api-reference)
- [Security Model](#security-model)
- [Prerequisites](#prerequisites)
- [Deployment Guide](#deployment-guide)
- [Local Development & Debug](#local-development--debug)
- [Testing](#testing)
- [Admin Dashboard](#admin-dashboard)
- [Configuration Reference](#configuration-reference)
- [Wrangler Commands Cheat Sheet](#wrangler-commands-cheat-sheet)
- [Cost Estimate](#cost-estimate)
- [Known Limitations & Phase 2](#known-limitations--phase-2)
- [Changelog](#changelog)
- [Troubleshooting](#troubleshooting)

---

## Architecture

```
                          ┌────────── INTERNET ──────────┐
                          │       (HTTPS / TLS)          │
                          └──────────────┬───────────────┘
                                         │
                    ┌────────────────────────────────────────────┐
                    │          CLOUDFLARE EDGE (Global)          │
                    │                                            │
                    │  ┌──────────────────┐  ┌───────────────┐  │
                    │  │  Workers (TS)    │  │ Pages (Static) │  │
                    │  │                  │  │                │  │
                    │  │  index.ts        │  │  login.html    │  │
                    │  │   ├─ auth.ts     │  │  index.html    │  │
                    │  │   ├─ admin.ts    │  │  api.js        │  │
                    │  │   ├─ middleware  │  │  styles.css    │  │
                    │  │   ├─ jwt.ts      │  │                │  │
                    │  │   ├─ db.ts       │  └───────────────┘  │
                    │  │   └─ utils.ts    │                      │
                    │  └────────┬─────────┘                      │
                    │           │                                 │
                    │     ┌─────┴──────┐    ┌─────────────────┐  │
                    │     │ D1 (SQLite) │    │ KV Namespaces   │  │
                    │     │             │    │                 │  │
                    │     │ tenants     │    │ CACHE    (TTL)  │  │
                    │     │ users       │    │ SESSIONS (TTL)  │  │
                    │     │ roles       │    │ BLACKLIST(TTL)  │  │
                    │     │ user_tenants│    │                 │  │
                    │     │ user_roles  │    └─────────────────┘  │
                    │     │ refresh_tkn │                         │
                    │     │ api_keys    │    ┌─────────────────┐  │
                    │     │ sessions    │    │ Secrets          │  │
                    │     │ audit_logs  │    │                 │  │
                    │     │ verify_tkn  │    │ JWT_PRIVATE_KEY │  │
                    │     │ rate_limits │    │ JWT_PUBLIC_KEY  │  │
                    │     └─────────────┘    │ SMTP_API_KEY    │  │
                    │                        └─────────────────┘  │
                    └────────────────────────────────────────────┘
```

### Request Flow

```
Request → Cloudflare Edge → Worker
  → CORS headers applied
  → Rate limiter checks KV (IP + endpoint)
  → Route matched in index.ts
  → If protected: JWT verified via middleware.ts
  → If admin: tenant resolved + role checked
  → Business logic in auth.ts / admin.ts
  → D1 query via db.ts (with KV cache layer)
  → Audit log written
  → JSON response returned
```

---

## Features

### Core Authentication
| Feature | Implementation | Details |
|---------|---------------|---------|
| Email/password login | `auth.ts` | PBKDF2 with 100,000 iterations, SHA-256 |
| JWT access tokens | `jwt.ts` | RS256 (RSA-PSS), 15-minute expiry |
| Refresh tokens | `jwt.ts`, `db.ts` | 7-day expiry, rotation with family-based reuse detection |
| Email verification | `auth.ts` | Time-limited tokens (24hr), SendGrid integration |
| Password reset | `auth.ts` | Forgot/reset flow with 1hr token expiry |
| Brute force protection | `middleware.ts` | 5 attempts per 15 min, auto account lock |
| Rate limiting | `middleware.ts` | Per IP + endpoint, KV-backed sliding window |
| CSRF protection | `middleware.ts` | Double-submit cookie pattern (skipped for Bearer/API-key auth) |
| First-time setup | `auth.ts` | `/api/auth/setup` — creates admin + default tenant (runs once) |

### Multi-Tenancy & RBAC
| Feature | Implementation | Details |
|---------|---------------|---------|
| Multi-tenant architecture | `schema.sql` | Tenant-scoped data isolation via foreign keys |
| Role-based access control | `middleware.ts`, `admin.ts` | Permissions checked per request |
| Multiple roles per user | `user_roles` junction | User can have different roles in different tenants |
| Tenant feature flags | `middleware.ts` | `checkFeature()` / `requireFeature()` reads tenant settings JSON |
| Cross-tenant users | `user_tenants` junction | Single user account, multiple tenant memberships |
| Default system roles | `auth.ts:setup()` | Creates admin, user, readonly on setup |

### Token & Key Management
| Feature | Implementation | Details |
|---------|---------------|---------|
| JWKS endpoint | `jwt.ts` | `GET /api/auth/jwks` — public key in JWK format |
| Token blacklist | `jwt.ts` | KV key `revoked:{jti}` with TTL matching token expiry |
| Token revocation | `jwt.ts` | By JTI — consistent key pattern in sign/verify/revoke |
| API keys | `admin.ts`, `db.ts` | CRUD with SHA-256 hash storage, prefix for identification |
| API key auth | `middleware.ts` | `X-API-Key` header, IP whitelist, per-key rate limits |
| Session management | `db.ts`, `admin.ts` | Track IP, user-agent, last activity per session |

### User Management
| Feature | Implementation | Details |
|---------|---------------|---------|
| User CRUD | `admin.ts` | Create, read, update, soft delete |
| Lock/unlock accounts | `admin.ts` | Lock with reason, unlock clears attempts |
| Force password reset | `admin.ts` | Sets flag, login response includes `force_password_reset: true` |
| Bulk import | `admin.ts` | POST array of `{email, password}` objects |
| Bulk export | `admin.ts` | GET all users as JSON |
| GDPR data export | `admin.ts`, `db.ts` | Full user data aggregate (profile, tenants, roles, sessions, audit) |
| Self-service export | `index.ts` | `GET /api/user/export` — user exports own data |

### Security & Compliance
| Feature | Implementation | Details |
|---------|---------------|---------|
| Audit logging | `db.ts` | Every auth event logged (90-day retention) |
| Security headers | `middleware.ts` | CSP, HSTS, X-Frame-Options, X-Content-Type-Options |
| Timing-safe compare | `utils.ts` | Constant-time password comparison |
| Webhook events | `utils.ts` | HMAC-signed, fire-and-forget on login/register |
| Password policy | `utils.ts` | Configurable min length, uppercase, numbers, special chars |
| Input sanitization | `utils.ts` | XSS prevention, length limits |

### Admin Dashboard
| Page | Features |
|------|----------|
| Login | Email/password login + first-time setup form |
| Dashboard | User count, active users (30d), login count, tenant count, recent activity |
| Users | CRUD, search, lock/unlock, force reset, sessions viewer, GDPR export, bulk export |
| Tenants | List, create, status badges, plan display |
| Roles | List, create with permissions, system role indicator |
| API Keys | Create with expiry/rate limit, revoke, key reveal on creation, copy button |
| Audit Logs | Paginated table with time, user, action, resource, IP, status |
| Settings | Change password, GDPR self-export |

---

## File Structure

```
auth-platform/                    21 files · ~3,350 lines total
│
├── schema.sql .............. 194 lines  D1 database schema (11 tables, indexes, triggers)
├── wrangler.json ............ 25 lines  Cloudflare Workers + D1 + KV bindings
├── package.json ............. 20 lines  Dependencies (@cloudflare/workers-types)
├── tsconfig.json ............ 12 lines  TypeScript strict config for Workers
├── deploy.sh ................ 28 lines  One-command deploy script (build check + deploy + migrate)
├── .env.example ............. 10 lines  Secrets template (JWT keys, SMTP)
├── .gitignore ............... 14 lines  Standard ignores
├── test.http ............... 150 lines  REST Client test file (every endpoint)
├── README.md                            This file
│
├── src/                               Backend TypeScript (1,969 lines)
│   ├── index.ts ........... 253 lines  Worker entry point, 39 route handlers
│   ├── auth.ts ............ 248 lines  Auth flows: login, register, setup, reset, refresh
│   ├── admin.ts ........... 262 lines  Admin API: users, roles, tenants, API keys, GDPR, bulk
│   ├── db.ts .............. 359 lines  D1 queries + KV cache (read-through, invalidation)
│   ├── jwt.ts ............. 185 lines  RS256 sign/verify, refresh rotation, JWKS, blacklist
│   ├── middleware.ts ...... 222 lines  CORS, auth, rate limit, CSRF, tenant, feature flags
│   ├── types.ts ........... 297 lines  All TypeScript interfaces (Env, User, Tenant, etc.)
│   └── utils.ts ........... 143 lines  PBKDF2 hashing, email, validation, webhooks
│
└── admin/                             Frontend SPA (782 lines)
    ├── login.html ......... 151 lines  Login form + first-time setup form
    ├── index.html ......... 421 lines  Full dashboard (7 pages, modals, all CRUD)
    ├── api.js ............. 145 lines  API client class (auth, users, roles, keys, etc.)
    └── styles.css ........... 65 lines  Dashboard styling (responsive, dark sidebar)
```

### File Responsibilities

| File | Depends On | Purpose |
|------|-----------|---------|
| `index.ts` | all src files | Entry point. Route matching. Wires middleware → handlers. |
| `auth.ts` | db, jwt, utils, types | Login, register, setup, logout, forgot/reset password, refresh |
| `admin.ts` | db, jwt, utils, types | All admin CRUD: users, roles, tenants, API keys, GDPR, bulk |
| `db.ts` | types | D1 queries. KV cache read-through. All data access. |
| `jwt.ts` | types | RS256 sign/verify. Refresh token rotation. JWKS. Token blacklist. |
| `middleware.ts` | jwt, db, utils, types | CORS, Bearer auth, API-key auth, rate limit, CSRF, tenant resolve |
| `types.ts` | — | All interfaces: Env, User, Tenant, Role, AuthContext, etc. |
| `utils.ts` | types | PBKDF2 hashing, email (SendGrid), validation, webhook dispatch |

---

## Database Schema

### 11 Tables

```sql
tenants              Tenant registry (slug, name, status, plan, settings JSON)
users                User accounts (email, password_hash, status, metadata JSON)
roles                Roles per tenant (name, permissions JSON array, is_system)
user_tenants         Junction: user ↔ tenant membership
user_roles           Junction: user ↔ tenant ↔ role assignment
refresh_tokens       Refresh tokens (hash, family_id for rotation detection)
api_keys             Machine-to-machine keys (hash, prefix, permissions, rate_limit)
verification_tokens  Email verify + password reset tokens (type, hash, expiry)
sessions             Active sessions (IP, user-agent, last_activity, expiry)
audit_logs           All auth events (action, resource, IP, success/fail)
rate_limits          Backup rate limiting (when KV unavailable)
```

### Key Columns Added (vs original spec)

| Table | Column | Type | Purpose |
|-------|--------|------|---------|
| `users` | `force_password_reset` | BOOLEAN DEFAULT 0 | Admin can force password change on next login |
| `api_keys` | `key_prefix` | TEXT | First 8 chars of key for identification without exposing full key |

If you already ran the original schema, apply these with:
```bash
wrangler d1 execute auth-platform-db --command="ALTER TABLE users ADD COLUMN force_password_reset BOOLEAN DEFAULT 0;" --remote
wrangler d1 execute auth-platform-db --command="ALTER TABLE api_keys ADD COLUMN key_prefix TEXT;" --remote
```

### Indexes (14 total)

All performance-critical queries are indexed: `users.email`, `users.status`, `user_tenants` (both directions), `user_roles` (composite), `refresh_tokens` (by user, by family), `api_keys` (by tenant), `verification_tokens` (by user), `sessions` (by user, active only), `audit_logs` (by tenant+date, by user+date), `rate_limits` (by window).

### Triggers

- `update_tenants_timestamp` — auto-updates `updated_at` on tenant modification
- `update_users_timestamp` — auto-updates `updated_at` on user modification

### Seed Data

The schema inserts a `system` tenant (id=1) with `INSERT OR IGNORE`, safe to re-run.

---

## API Reference

### Public Endpoints (no auth required)

| Method | Endpoint | Request Body | Response | Notes |
|--------|----------|-------------|----------|-------|
| GET | `/health` | — | `{status: "ok"}` | Health check |
| POST | `/api/auth/setup` | `{email, password, tenant_name, tenant_slug}` | `{user, tenant, roles}` | First-time only. Fails if users exist. |
| POST | `/api/auth/register` | `{email, password, tenant_slug}` | `{user, verification_sent}` | Creates pending user, sends verify email |
| POST | `/api/auth/login` | `{email, password, tenant_slug, remember_me?}` | `{access_token, refresh_token, user, tenant, roles}` | Returns `force_password_reset` if flagged |
| POST | `/api/auth/refresh` | `{refresh_token}` | `{access_token, refresh_token}` | Rotates refresh token. Detects family reuse. |
| POST | `/api/auth/forgot-password` | `{email}` | `{message}` | Always returns success (prevents enumeration) |
| POST | `/api/auth/reset-password` | `{token, new_password}` | `{message}` | Token from forgot-password email |
| POST | `/api/auth/verify-email` | `{token}` | `{message}` | Token from verification email |
| GET | `/api/auth/jwks` | — | `{keys: [{kty, n, e, ...}]}` | RS256 public key in JWK format |

### Authenticated Endpoints (Bearer token required)

| Method | Endpoint | Request Body | Response | Notes |
|--------|----------|-------------|----------|-------|
| POST | `/api/auth/logout` | — | `{message}` | Blacklists token JTI in KV |
| POST | `/api/auth/change-password` | `{current_password, new_password}` | `{message}` | Validates current password first |
| GET | `/api/user/profile` | — | `{user}` | Current user profile |
| PUT | `/api/user/profile` | `{metadata}` | `{user}` | Update profile metadata |
| GET | `/api/user/export` | — | `{user, tenants, roles, sessions, audit}` | GDPR self-service data export |

### Admin Endpoints (Bearer + `X-Tenant-Slug` header required)

**Users**

| Method | Endpoint | Body / Params | Response |
|--------|----------|---------------|----------|
| GET | `/api/admin/users?page=1&limit=20&search=` | Query params | `{items, page, pages, total}` |
| POST | `/api/admin/users` | `{email, password, status?}` | `{user}` |
| GET | `/api/admin/users/:id` | — | `{user}` |
| PUT | `/api/admin/users/:id` | `{email?, status?, metadata?}` | `{user}` |
| DELETE | `/api/admin/users/:id` | — | `{message}` (soft delete) |
| POST | `/api/admin/users/:id/lock` | `{reason}` | `{message}` |
| POST | `/api/admin/users/:id/unlock` | — | `{message}` |
| POST | `/api/admin/users/:id/force-reset` | — | `{message}` (sets flag + revokes refresh tokens) |
| GET | `/api/admin/users/:id/sessions` | — | `{sessions}` |
| DELETE | `/api/admin/users/:id/sessions/:sid` | — | `{message}` |
| GET | `/api/admin/users/:id/export` | — | `{user, tenants, roles, sessions, audit}` |
| GET | `/api/admin/users/export` | Query params | `{users}` (bulk export) |
| POST | `/api/admin/users/import` | `{users: [{email, password}]}` | `{imported, errors}` |

**Roles**

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| GET | `/api/admin/roles` | — | `{roles}` |
| POST | `/api/admin/roles` | `{name, permissions: string[]}` | `{role}` |
| POST | `/api/admin/users/:id/roles` | `{role_id}` | `{message}` |
| DELETE | `/api/admin/users/:id/roles/:rid` | — | `{message}` |

**Tenants**

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| GET | `/api/admin/tenants` | — | `{tenants}` |
| POST | `/api/admin/tenants` | `{name, slug}` | `{tenant}` |

**API Keys**

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| GET | `/api/admin/api-keys` | — | `{api_keys}` |
| POST | `/api/admin/api-keys` | `{name, permissions, expires_in_days?, rate_limit?}` | `{api_key, raw_key}` (raw_key shown once) |
| DELETE | `/api/admin/api-keys/:id` | — | `{message}` |

**Audit & Stats**

| Method | Endpoint | Params | Response |
|--------|----------|--------|----------|
| GET | `/api/admin/audit-logs?page=1&limit=20` | Query params | `{items, page, pages}` |
| GET | `/api/admin/stats` | — | `{users, activeUsers, logins, tenants}` |

### API Key Auth

| Method | Endpoint | Header | Response |
|--------|----------|--------|----------|
| GET | `/api/protected` | `X-API-Key: <raw_key>` | `{message, key_name}` |

### Response Format

All responses follow this structure:

```json
// Success
{ "success": true, "data": { ... } }

// Error
{ "success": false, "error": { "code": "INVALID_CREDENTIALS", "message": "...", "timestamp": "..." } }
```

HTTP status codes: 200 (success), 201 (created), 400 (bad request), 401 (unauthorized), 403 (forbidden), 404 (not found), 429 (rate limited), 500 (server error).

---

## Security Model

### Password Security
- **Algorithm**: PBKDF2 with SHA-256, 100,000 iterations, 16-byte random salt
- **Note**: Spec originally called for Argon2id, but Cloudflare Workers lacks native Argon2 support. PBKDF2-100k is the recommended Workers-compatible alternative. Upgrade path: use `@noble/hashes` for Argon2 when WASM support matures.
- **Storage format**: `pbkdf2$<base64_salt>$<base64_hash>`
- **Comparison**: Timing-safe (constant-time XOR comparison)

### JWT Tokens
- **Algorithm**: RS256 (RSA-PKCS1-v1_5 with SHA-256)
- **Access token**: 15-minute expiry, contains `{sub, email, tenant_id, roles[], jti}`
- **Refresh token**: 7-day expiry, stored as SHA-256 hash in D1
- **Rotation**: Each refresh generates new access + refresh pair. Old refresh token invalidated.
- **Family detection**: If a revoked refresh token is reused, the entire token family is revoked (detects stolen tokens)
- **Revocation**: Token JTI stored in KV `BLACKLIST` with TTL matching remaining token lifetime

### Rate Limiting
- **Login**: 5 attempts per 15 minutes per IP
- **Register**: 3 per hour per IP
- **API endpoints**: 100 per minute per IP (configurable)
- **API keys**: Per-key rate limit (default 1000/hr)
- **Storage**: KV with sliding window. Fallback to D1 `rate_limits` table.

### Headers Applied to Every Response
```
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
```

### Brute Force Protection
After 5 failed login attempts within 15 minutes, the account is automatically locked. Admin must unlock via `/api/admin/users/:id/unlock` or the user must wait for the window to expire.

### CSRF Protection
Double-submit cookie pattern. Automatically skipped for stateless auth (Bearer token or API key), enforced for cookie-based session flows.

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Node.js | 18+ | `brew install node` or [nodejs.org](https://nodejs.org) |
| Wrangler CLI | Latest | `npm install -g wrangler` |
| OpenSSL | Any | Pre-installed on macOS/Linux |
| Cloudflare account | Free tier works | [dash.cloudflare.com](https://dash.cloudflare.com) |
| VS Code (optional) | Latest | With REST Client extension for `test.http` |

---

## Deployment Guide

### Step 1: Install Dependencies

```bash
cd auth-platform
npm install
```

### Step 2: Create Cloudflare Resources

```bash
# Authenticate (opens browser)
wrangler login

# Create D1 Database
wrangler d1 create auth-platform-db
# → Copy the database_id

# Create 3 KV Namespaces
wrangler kv:namespace create "CACHE"
wrangler kv:namespace create "SESSIONS"
wrangler kv:namespace create "BLACKLIST"
# → Copy each id
```

### Step 3: Update wrangler.json

Replace all `REPLACE_WITH_YOUR_*` placeholders with the IDs from Step 2:

```toml
[[d1_databases]]
binding = "DB"
database_name = "auth-platform-db"
database_id = "YOUR_D1_ID_HERE"

[[kv_namespaces]]
binding = "CACHE"
id = "YOUR_CACHE_KV_ID_HERE"

[[kv_namespaces]]
binding = "SESSIONS"
id = "YOUR_SESSIONS_KV_ID_HERE"

[[kv_namespaces]]
binding = "BLACKLIST"
id = "YOUR_BLACKLIST_KV_ID_HERE"
```

### Step 4: Generate JWT Keys

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

### Step 5: Set Secrets

```bash
wrangler secret put JWT_PRIVATE_KEY < private.pem
wrangler secret put JWT_PUBLIC_KEY < public.pem
wrangler secret put SMTP_API_KEY
# → Paste SendGrid/Resend API key, press Enter
```

### Step 6: Initialize Database

```bash
wrangler d1 execute auth-platform-db --file=schema.sql --remote
```

### Step 7: Deploy Worker

```bash
wrangler deploy
# → Deployed to https://auth-platform.YOUR-SUBDOMAIN.workers.dev
```

### Step 8: First-Time Setup

```bash
curl -X POST https://auth-platform.YOUR-SUBDOMAIN.workers.dev/api/auth/setup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@yourdomain.com",
    "password": "YourStrongPassword123!",
    "tenant_name": "My Company",
    "tenant_slug": "my-company"
  }'
```

### Step 9: Deploy Admin Dashboard

```bash
# Before deploying, update api.js baseUrl for production:
# Change: ? 'http://localhost:8787/api' : '/api'
# To:     ? 'http://localhost:8787/api' : 'https://auth-platform.YOUR-SUB.workers.dev/api'

wrangler pages project create authnex-admin
wrangler pages deploy admin --project-name=authnex-admin
# → Dashboard at https://authnex-admin.pages.dev
```

### GitHub Auto-Deploy (if connected)

If your Cloudflare account is connected to GitHub:

1. Push code to your GitHub repo
2. In Cloudflare Dashboard → Workers & Pages → your worker
3. Set Build command: `npm install` (or leave blank for static)
4. Set Output directory: `/` for Worker, `admin/` for Pages
5. Every push to `main` triggers auto-deploy

---

## Local Development & Debug

### Start Local Dev Server

```bash
# Copy secrets template
cp .env.example .dev.vars
# Edit .dev.vars — paste your JWT keys and SMTP key

# Initialize local database
npx wrangler d1 execute auth-platform-db --file=schema.sql --local

# Start dev server (auto-reloads on file save)
npx wrangler dev
# → http://localhost:8787
```

### Local vs Production

| | Local (`wrangler dev`) | Production (`wrangler deploy`) |
|---|---|---|
| URL | `http://localhost:8787` | `https://auth-platform.xxx.workers.dev` |
| Database | Local SQLite file in `.wrangler/` | Cloudflare D1 |
| KV | Emulated locally | Cloudflare KV |
| Secrets | Read from `.dev.vars` | From `wrangler secret put` |
| Hot reload | Yes (auto on save) | No (requires `wrangler deploy`) |

### Debug Workflow

```
1. Edit code in VS Code → Save (Ctrl+S)
2. wrangler dev auto-reloads (watch terminal for errors)
3. Test with curl / test.http / browser
4. Error? → Read terminal output (stack trace shown)
5. Fix → Save → Auto-reload → Test again
6. Working? → wrangler deploy
```

### Check TypeScript Errors (without deploying)

```bash
npx tsc --noEmit
```

### Live Production Logs

```bash
# Stream real-time logs from production
wrangler tail
# Shows every request + response + errors
# Ctrl+C to stop
```

### Query Database Directly

```bash
# Local
npx wrangler d1 execute auth-platform-db --command="SELECT * FROM users" --local

# Production
npx wrangler d1 execute auth-platform-db --command="SELECT * FROM users" --remote

# Count tables
npx wrangler d1 execute auth-platform-db --command="SELECT name FROM sqlite_master WHERE type='table'" --remote
```

---

## Testing

### Using test.http (VS Code REST Client)

1. Install VS Code extension: **REST Client** by Huachao Mao
2. Open `test.http`
3. Update `@baseUrl` at the top (localhost or production URL)
4. Click **"Send Request"** above any request block
5. Response appears in split panel

### Testing Flow (recommended order)

```
1. GET  /health                        → Verify worker is running
2. POST /api/auth/setup                → Bootstrap admin (first time only)
3. POST /api/auth/login                → Get access_token + refresh_token
4. Copy access_token → paste into @token variable in test.http
5. GET  /api/admin/stats               → Verify admin access works
6. POST /api/admin/users               → Create a test user
7. GET  /api/admin/users               → List users
8. POST /api/auth/register             → Test public registration
9. POST /api/auth/refresh              → Test token rotation
10. POST /api/auth/logout              → Test token revocation
11. POST /api/admin/api-keys           → Create API key
12. GET  /api/protected (X-API-Key)    → Test API key auth
```

### Quick curl Tests

```bash
BASE=http://localhost:8787  # or your production URL

# Health
curl $BASE/health

# Login
curl -s -X POST $BASE/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.com","password":"Test1234!","tenant_slug":"my-company"}' | jq .

# Use token
TOKEN="paste_token_here"
curl -s $BASE/api/admin/stats \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-Slug: my-company" | jq .
```

---

## Admin Dashboard

### Pages

| Page | URL | Description |
|------|-----|-------------|
| Login | `/login.html` | Email/password + setup toggle |
| Dashboard | `/index.html#dashboard` | Stats cards + recent activity |
| Users | `/index.html#users` | Full user management with actions |
| Tenants | `/index.html#tenants` | Tenant list + create |
| Roles | `/index.html#roles` | Role list + create with permissions |
| API Keys | `/index.html#apikeys` | Key management + one-time key reveal |
| Audit Logs | `/index.html#audit` | Paginated event log |
| Settings | `/index.html#settings` | Change password + GDPR export |

### Tech Stack
- Bootstrap 5.3 (CDN)
- Bootstrap Icons (CDN)
- Vanilla JavaScript (no build step)
- Single `api.js` client with auto token refresh

### Token Auto-Refresh
The `api.js` client checks token expiry every 60 seconds. If the access token expires within 5 minutes, it automatically refreshes using the stored refresh token.

---

## Configuration Reference

### wrangler.json

```toml
name = "auth-platform"               # Worker name in Cloudflare
main = "src/index.ts"                 # Entry point
compatibility_date = "2024-01-01"     # Workers runtime version

[[d1_databases]]
binding = "DB"                        # Accessed as env.DB in code
database_name = "auth-platform-db"
database_id = "..."                   # From wrangler d1 create

[[kv_namespaces]]
binding = "CACHE"                     # env.CACHE — user/tenant data cache
id = "..."

[[kv_namespaces]]
binding = "SESSIONS"                  # env.SESSIONS — active sessions
id = "..."

[[kv_namespaces]]
binding = "BLACKLIST"                 # env.BLACKLIST — revoked token JTIs
id = "..."

[vars]
ENVIRONMENT = "production"            # "development" enables stack traces
```

### Secrets (set via `wrangler secret put`)

| Secret | Purpose | How to Generate |
|--------|---------|----------------|
| `JWT_PRIVATE_KEY` | Signs access tokens (RS256) | `openssl genrsa -out private.pem 2048` |
| `JWT_PUBLIC_KEY` | Verifies tokens + JWKS endpoint | `openssl rsa -in private.pem -pubout -out public.pem` |
| `SMTP_API_KEY` | SendGrid/Resend email API key | From your email provider dashboard |

### .dev.vars (local development only)

```env
JWT_PRIVATE_KEY=<paste full PEM content>
JWT_PUBLIC_KEY=<paste full PEM content>
SMTP_API_KEY=your_sendgrid_key
SMTP_FROM=noreply@yourdomain.com
ENVIRONMENT=development
```

### Environment-Specific Behavior

| Setting | Development | Production |
|---------|------------|------------|
| Error responses | Include stack trace | User-friendly message only |
| CORS | `localhost:*` allowed | Restrict to your domain |
| Rate limits | Same logic, local KV | Cloudflare KV |

---

## Wrangler Commands Cheat Sheet

| Command | Purpose |
|---------|---------|
| `npx wrangler dev` | Start local dev server (hot reload) |
| `npx wrangler deploy` | Deploy to Cloudflare production |
| `npx wrangler tail` | Stream live production logs |
| `npx wrangler d1 list` | List all D1 databases |
| `npx wrangler d1 execute DB --command="SQL" --local` | Query local DB |
| `npx wrangler d1 execute DB --command="SQL" --remote` | Query production DB |
| `npx wrangler d1 execute DB --file=schema.sql --remote` | Run schema file on production |
| `npx wrangler d1 backup create DB` | Backup production database |
| `npx wrangler d1 backup list DB` | List backups |
| `npx wrangler d1 backup restore DB BACKUP_ID` | Restore a backup |
| `npx wrangler kv:namespace list` | List KV namespaces |
| `npx wrangler secret list` | List configured secrets |
| `npx wrangler secret put NAME` | Set/update a secret |
| `npx wrangler secret delete NAME` | Remove a secret |
| `npx wrangler pages deploy admin --project-name=X` | Deploy admin dashboard |
| `npx tsc --noEmit` | TypeScript type check (no build output) |

---

## Cost Estimate

### 25,000 Monthly Active Users

| Service | Usage | Cost |
|---------|-------|------|
| Workers | ~10M requests/month | $5.00 |
| D1 | ~5M reads, 500K writes, 500MB storage | $6.25 |
| KV | ~10M reads, 1M writes | $10.50 |
| Pages | Unlimited sites, 500 deploys | Free |
| Secrets | Unlimited | Free |
| **Total** | | **~$22/month** |

### Free Tier (suitable for dev/staging)

| Service | Free Allowance |
|---------|---------------|
| Workers | 100K requests/day |
| D1 | 5M reads, 100K writes, 5GB storage |
| KV | 100K reads, 1K writes per day |
| Pages | 500 deploys/month |

---

## Known Limitations & Phase 2

### Current Limitations

| Item | Status | Notes |
|------|--------|-------|
| PBKDF2 instead of Argon2id | Intentional | Workers lack native Argon2. PBKDF2-100k is secure. |
| No OIDC endpoints | Phase 2 | `/.well-known/openid-configuration`, `/userinfo`, `/authorize` not yet built |
| No SDK libraries | Phase 2 | JavaScript and PHP SDKs planned |
| No social login | Phase 2 | Google, Microsoft OAuth planned |
| No 2FA / TOTP | Phase 2 | Two-factor authentication planned |
| No WebAuthn/Passkeys | Phase 2 | Passwordless auth planned |
| No tenant branding | Phase 2 | Custom logos, colors per tenant |
| KV rate limit race condition | Documented | `get` then `put` is not atomic. Acceptable at expected scale. |
| No widget/embed system | Phase 2 | Drop-in login widget planned |

### Phase 2 Roadmap

1. **OIDC Compliance** — `/.well-known/openid-configuration`, `/authorize`, `/token`, `/userinfo`
2. **Social Login** — Google, Microsoft OAuth2 providers
3. **Two-Factor Auth** — TOTP (Google Authenticator, Authy)
4. **WebAuthn/Passkeys** — Passwordless authentication
5. **Tenant Branding** — Custom login pages per tenant
6. **JS/PHP SDKs** — Client libraries for common platforms
7. **Advanced Audit Analytics** — Dashboards, alerting, anomaly detection

---

## Changelog

### v1.0.0 — Initial Release

**Critical Fixes (P0) from Review:**
- Fixed token blacklist key inconsistency (`jwt.ts` — `sign()` no longer stores JTI; `revoke()` and `verify()` use consistent `revoked:{jti}` pattern)
- Fixed immutable `request.headers.set()` crash (`middleware.ts` — token now passed via `AuthContext.token` field)
- Wired CSRF protection (`middleware.ts` — skips Bearer/API-key auth, ready for cookie-based flows)
- Added first-time setup endpoint (`POST /api/auth/setup`)
- Created all missing config files (`wrangler.json`, `package.json`, `tsconfig.json`)

**Features Added (P1):**

- Admin login page (`admin/login.html`) with setup form
- API key management: create, list, revoke with hash storage + prefix
- API key authentication middleware with IP whitelist + rate limits
- Force password reset: admin sets flag, login response includes it
- Session/device management: view and revoke per user
- Cache invalidation fix: clears all tenant-scoped email + role caches
- Admin `api.js`: fixed GET requests sending body

**Features Added (P2):**
- GDPR data export (admin endpoint + self-service)
- Bulk user export
- Webhook event dispatcher (HMAC-signed, fire-and-forget)
- Tenant feature flags middleware (`checkFeature()` / `requireFeature()`)
- Roles page in admin dashboard
- Settings page in admin dashboard
- API Keys page in admin dashboard with key reveal + copy

**Schema Changes:**
- Added `users.force_password_reset` column (BOOLEAN DEFAULT 0)
- Added `api_keys.key_prefix` column (TEXT)

---

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|---------|
| `wrangler deploy` fails with type errors | Missing dependencies | Run `npm install` first |
| `wrangler deploy` says "No such module" | Build issue | Run `npm run build && wrangler deploy` |
| 500 error on any endpoint | Runtime error | Run `wrangler tail` to see stack trace |
| 401 Unauthorized on all requests | JWT secrets wrong/missing | `wrangler secret list` → re-set JWT keys |
| "Token revoked" immediately after login | Blacklist key mismatch | Ensure `jwt.ts` uses `revoked:{jti}` pattern (fixed in v1) |
| Setup returns "already initialized" | Setup ran before | Login with your admin credentials instead |
| CORS errors in admin dashboard | API URL mismatch | Update `api.js` baseUrl to your worker URL |
| Admin dashboard blank page | JS error | Open browser console (F12) → check errors |
| "No such table" on any query | Schema not applied | Re-run: `wrangler d1 execute auth-platform-db --file=schema.sql --remote` |
| Email not sending | SMTP_API_KEY wrong | `wrangler secret put SMTP_API_KEY` with correct key |
| Rate limited (429) during testing | Rate limiter active | Wait 15 min or clear KV: `wrangler kv:key delete CACHE "rate:..."` |
| `force_password_reset` column missing | Schema change not applied | `wrangler d1 execute auth-platform-db --command="ALTER TABLE users ADD COLUMN force_password_reset BOOLEAN DEFAULT 0;" --remote` |
| `key_prefix` column missing | Schema change not applied | `wrangler d1 execute auth-platform-db --command="ALTER TABLE api_keys ADD COLUMN key_prefix TEXT;" --remote` |
| Local dev can't find secrets | `.dev.vars` missing | Copy `.env.example` to `.dev.vars` and fill in values |
| TypeScript errors in VS Code | Types not installed | `npm install` → `@cloudflare/workers-types` provides type definitions |

---

## License

MIT
