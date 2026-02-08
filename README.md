# AuthNex — Multi-Tenant Authentication Platform

> Pure Cloudflare Workers + D1 + KV · TypeScript · Zero Infrastructure

## Architecture

```
┌─────────────────────── CLOUDFLARE EDGE ───────────────────────┐
│                                                                │
│  Workers (TypeScript)           D1 (SQLite)     KV Stores      │
│  ┌────────────────────┐        ┌──────────┐    ┌───────────┐  │
│  │ Auth · Admin · API │───────▶│ Users    │    │ Cache     │  │
│  │ Setup · JWKS       │        │ Tenants  │    │ Sessions  │  │
│  └────────────────────┘        │ Roles    │    │ Blacklist │  │
│                                │ Audit    │    └───────────┘  │
│  Pages (Static SPA)            │ Tokens   │                    │
│  ┌────────────────────┐        └──────────┘                    │
│  │ Admin Dashboard    │                                        │
│  └────────────────────┘                                        │
└────────────────────────────────────────────────────────────────┘
```

## Features

### Core Auth
- Email/password login with PBKDF2 (100k iterations)
- JWT access tokens (RS256, 15-min expiry)
- Refresh token rotation with family-based reuse detection
- Email verification & password reset flows
- Brute force protection (5 attempts / 15 min, auto-lock)
- Rate limiting per IP/endpoint via KV
- First-time system setup endpoint

### Multi-Tenancy & RBAC
- Tenant-scoped role-based access control
- Multiple roles per user per tenant
- Tenant-level feature flags
- Cross-tenant user support
- Default roles: admin, user, readonly

### Token & Key Management
- JWKS endpoint for public key distribution
- Token blacklist via KV (JTI-based)
- API keys with CRUD, rate limits, IP whitelist
- Session/device management (view & revoke)

### Admin Dashboard
- Full SPA (login + dashboard)
- User CRUD, lock/unlock, force password reset
- Bulk import/export users
- Role & tenant management
- API key management (create, revoke)
- Session viewer per user
- Audit log viewer with pagination
- GDPR data export (admin + self-service)
- Stats dashboard

### Security
- CSRF protection (double-submit cookie)
- Security headers (CSP, HSTS, X-Frame-Options)
- Timing-safe password comparison
- Webhook dispatch on key events (login, register)
- Audit logging (90-day retention)

## File Structure (19 files)

```
auth-platform/
├── schema.sql              # D1 database schema
├── wrangler.toml           # Cloudflare config
├── package.json            # Dependencies
├── tsconfig.json           # TypeScript config
├── deploy.sh               # One-command deploy
├── .env.example            # Secrets template
├── .gitignore
├── test.http               # REST client tests
├── README.md
├── src/
│   ├── index.ts            # Worker entry + routes
│   ├── auth.ts             # Auth flows (login, register, reset, setup)
│   ├── admin.ts            # Admin API (users, roles, tenants, keys, GDPR)
│   ├── db.ts               # D1 queries + KV cache
│   ├── jwt.ts              # RS256 sign/verify, refresh rotation, JWKS
│   ├── middleware.ts        # CORS, auth, rate limit, CSRF, tenant
│   ├── types.ts            # TypeScript interfaces
│   └── utils.ts            # Hashing, validation, email, webhooks
└── admin/
    ├── login.html           # Login + first-time setup
    ├── index.html           # Dashboard SPA
    ├── api.js               # API client
    └── styles.css           # Styling
```

## Quick Start

### Prerequisites
- Node.js 18+
- Wrangler CLI: `npm install -g wrangler`
- Cloudflare account

### 1. Clone & Install
```bash
git clone https://github.com/YOUR_USERNAME/auth-platform.git
cd auth-platform
npm install
```

### 2. Authenticate Wrangler
```bash
wrangler login
```

### 3. Create Cloudflare Resources
```bash
# D1 Database
wrangler d1 create auth-platform-db
# Copy the database_id to wrangler.toml

# KV Namespaces
wrangler kv:namespace create "CACHE"
wrangler kv:namespace create "SESSIONS"
wrangler kv:namespace create "BLACKLIST"
# Copy each id to wrangler.toml
```

### 4. Update wrangler.toml
Replace all `REPLACE_WITH_YOUR_*` placeholders with real IDs.

### 5. Generate JWT Keys
```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

### 6. Set Secrets
```bash
wrangler secret put JWT_PRIVATE_KEY < private.pem
wrangler secret put JWT_PUBLIC_KEY < public.pem
wrangler secret put SMTP_API_KEY
# Paste your SendGrid/Resend API key
```

### 7. Initialize Database
```bash
wrangler d1 execute auth-platform-db --file=schema.sql --remote
```

### 8. Deploy
```bash
wrangler deploy
```

### 9. First-Time Setup
```bash
curl -X POST https://YOUR-WORKER.workers.dev/api/auth/setup \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"AdminPass123!","tenant_name":"My Company","tenant_slug":"my-company"}'
```

### 10. Deploy Admin Dashboard
```bash
wrangler pages project create authnex-admin
wrangler pages deploy admin --project-name=authnex-admin
```

## Local Development

```bash
# Copy env template
cp .env.example .dev.vars
# Edit .dev.vars with your keys

# Init local DB
npm run db:init:local

# Start dev server
npm run dev
# → http://localhost:8787
```

## API Endpoints

### Public
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/setup` | First-time system init |
| POST | `/api/auth/register` | Register user |
| POST | `/api/auth/login` | Login |
| POST | `/api/auth/refresh` | Refresh token |
| POST | `/api/auth/forgot-password` | Request reset |
| POST | `/api/auth/reset-password` | Reset password |
| POST | `/api/auth/verify-email` | Verify email |
| GET | `/api/auth/jwks` | Public keys |
| GET | `/health` | Health check |

### Authenticated
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/logout` | Logout |
| POST | `/api/auth/change-password` | Change password |
| GET | `/api/user/profile` | Get profile |
| PUT | `/api/user/profile` | Update profile |
| GET | `/api/user/export` | GDPR self-export |

### Admin (requires Bearer + X-Tenant-Slug)
| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/api/admin/users` | List / Create users |
| GET/PUT/DELETE | `/api/admin/users/:id` | Get / Update / Delete |
| POST | `/api/admin/users/:id/lock` | Lock account |
| POST | `/api/admin/users/:id/unlock` | Unlock account |
| POST | `/api/admin/users/:id/force-reset` | Force password reset |
| GET | `/api/admin/users/:id/sessions` | View sessions |
| DELETE | `/api/admin/users/:id/sessions/:sid` | Revoke session |
| GET | `/api/admin/users/:id/export` | GDPR export |
| GET | `/api/admin/users/export` | Bulk export |
| POST | `/api/admin/users/import` | Bulk import |
| GET/POST | `/api/admin/roles` | List / Create roles |
| POST | `/api/admin/users/:id/roles` | Assign role |
| DELETE | `/api/admin/users/:id/roles/:rid` | Remove role |
| GET/POST | `/api/admin/tenants` | List / Create tenants |
| GET/POST | `/api/admin/api-keys` | List / Create API keys |
| DELETE | `/api/admin/api-keys/:id` | Revoke API key |
| GET | `/api/admin/audit-logs` | Audit logs |
| GET | `/api/admin/stats` | Statistics |

### API Key Auth
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/protected` | Test API key (X-API-Key header) |

## Cost Estimate (25k MAU)

| Service | Cost |
|---------|------|
| Workers (10M req) | $5.00 |
| D1 Storage + Queries | $6.25 |
| KV (10M reads, 1M writes) | $10.50 |
| Pages | Free |
| **Total** | **~$22/month** |

## Maintenance

```bash
# View live logs
wrangler tail

# Backup database
wrangler d1 backup create auth-platform-db

# Update secrets
wrangler secret put SECRET_NAME

# Deploy update
wrangler deploy
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| "No such module" | `npm run build && wrangler deploy` |
| 401 Unauthorized | Check JWT secrets: `wrangler secret list` |
| DB not found | Verify D1 ID in wrangler.toml: `wrangler d1 list` |
| CORS errors | Update allowed origins in middleware.ts |
| Setup fails | Ensure no users exist yet (runs only once) |
| Email not sending | Verify SMTP_API_KEY secret |

## License

MIT
