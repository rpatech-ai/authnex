# API Reference

Complete reference for all AuthNex API endpoints.

## Base URL

All API requests are made to your AuthNex worker URL:

```
https://your-authnex-instance.workers.dev
```

## Authentication

**Bearer Token** — For user-authenticated requests:

```
Authorization: Bearer <access_token>
```

**API Key** — For machine-to-machine requests:

```
X-API-Key: ak_xxxxxxxx_xxxxxxxx
```

**Tenant Header** — Required for admin endpoints:

```
X-Tenant-Slug: your-tenant-slug
```

## Response Format

All responses follow this format:

```json
{
  "success": true,
  "data": { ... }
}
```

Error responses:

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable message",
    "timestamp": "2026-02-09T00:00:00.000Z"
  }
}
```

## Public Endpoints

### POST /api/auth/setup

First-time system initialization. Creates the system tenant and admin user.

**Body:**

```json
{
  "email": "admin@example.com",
  "password": "SecurePass123",
  "tenant_name": "My Company",
  "tenant_slug": "my-company"
}
```

**Response:** `201`

```json
{
  "user": { "id": 1, "email": "admin@example.com", "status": "active" },
  "tenant": { "id": 1, "name": "My Company", "slug": "my-company" }
}
```

### POST /api/auth/login

Authenticate a user with email and password.

**Body:**

```json
{
  "email": "user@example.com",
  "password": "MyPassword123",
  "tenant_slug": "my-company",
  "remember_me": true
}
```

**Response:** `200`

```json
{
  "access_token": "eyJ...",
  "refresh_token": "uuid.family.random",
  "expires_in": 900,
  "user": { "id": 1, "email": "user@example.com", "status": "active" },
  "tenant": { "id": 1, "name": "My Company", "slug": "my-company" }
}
```

### POST /api/auth/register

Register a new user account.

**Body:**

```json
{
  "email": "newuser@example.com",
  "password": "SecurePass123",
  "tenant_slug": "my-company",
  "metadata": { "name": "John Doe" }
}
```

**Response:** `201` — A verification email is sent automatically.

### POST /api/auth/verify-email

Verify a user's email address.

**Body:**

```json
{ "token": "verification-token-from-email" }
```

### POST /api/auth/forgot-password

Request a password reset email.

**Body:**

```json
{ "email": "user@example.com" }
```

**Response:** `200` — Always returns success (prevents email enumeration).

### POST /api/auth/reset-password

Reset password with a token from the reset email.

**Body:**

```json
{
  "token": "reset-token-from-email",
  "password": "NewSecurePass123"
}
```

### POST /api/auth/refresh

Refresh an expired access token.

**Body:**

```json
{ "refresh_token": "current-refresh-token" }
```

**Response:** Returns new `access_token` and `refresh_token` (old refresh token is revoked).

### GET /api/auth/jwks

Get the public key for JWT verification.

**Response:**

```json
{
  "keys": [{
    "kty": "RSA",
    "kid": "primary",
    "use": "sig",
    "alg": "RS256",
    "n": "...",
    "e": "AQAB"
  }]
}
```

### POST /api/signup

Self-service tenant signup (creates tenant + admin user + API key).

**Body:**

```json
{
  "email": "owner@company.com",
  "password": "SecurePass123",
  "company_name": "Acme Corp",
  "tenant_slug": "acme-corp",
  "plan": "free"
}
```

**Response:** `201`

```json
{
  "user": { "id": 5, "email": "owner@company.com" },
  "tenant": { "id": 3, "name": "Acme Corp", "slug": "acme-corp", "plan": "free" },
  "api_key": "ak_xxxxxxxx_full-key-shown-once",
  "access_token": "eyJ...",
  "refresh_token": "uuid.family.random"
}
```

### GET /api/plans

List available subscription plans.

### GET /api/check-slug?slug=my-slug

Check if a tenant slug is available.

## Protected Endpoints

Require `Authorization: Bearer <token>` header.

### POST /api/auth/logout

Revoke all tokens and sessions.

### POST /api/auth/change-password

**Body:**

```json
{
  "current_password": "OldPass123",
  "new_password": "NewPass123"
}
```

### GET /api/user/profile

Get the current user's profile.

### PUT /api/user/profile

Update profile metadata.

**Body:**

```json
{ "metadata": { "name": "Updated Name" } }
```

### GET /api/user/export

GDPR self-service data export.

## Portal Endpoints

Require authentication + tenant membership.

### GET /api/portal/dashboard

Get customer dashboard stats (users, usage, plan info).

### GET /api/portal/users

List tenant users. Supports `?page=1&limit=20&search=email`.

### GET /api/portal/usage

Get current month API usage breakdown.

## Admin Endpoints

Require `Authorization: Bearer <token>` and `X-Tenant-Slug` headers.

### Users

| Method | Endpoint | Permission | Description |
|--------|----------|------------|-------------|
| GET | `/api/admin/users` | `users:read` | List users (paginated, searchable) |
| POST | `/api/admin/users` | `users:create` | Create user |
| GET | `/api/admin/users/:id` | `users:read` | Get user details |
| PUT | `/api/admin/users/:id` | `users:update` | Update user |
| DELETE | `/api/admin/users/:id` | `users:delete` | Soft delete user |
| POST | `/api/admin/users/:id/lock` | `users:update` | Lock user account |
| POST | `/api/admin/users/:id/unlock` | `users:update` | Unlock user account |
| POST | `/api/admin/users/:id/force-reset` | `users:update` | Force password reset |
| GET | `/api/admin/users/:id/sessions` | `users:read` | List user sessions |
| DELETE | `/api/admin/users/:id/sessions/:sid` | `users:update` | Revoke session |
| GET | `/api/admin/users/:id/export` | `users:read` | GDPR data export |
| POST | `/api/admin/users/:id/roles` | `users:update` | Assign role |
| DELETE | `/api/admin/users/:id/roles/:rid` | `users:update` | Remove role |
| GET | `/api/admin/users/export` | `users:read` | Bulk export users |
| POST | `/api/admin/users/import` | `users:create` | Bulk import users |

### Roles

| Method | Endpoint | Permission | Description |
|--------|----------|------------|-------------|
| GET | `/api/admin/roles` | `roles:read` | List roles |
| POST | `/api/admin/roles` | `roles:create` | Create role |

### Tenants

| Method | Endpoint | Permission | Description |
|--------|----------|------------|-------------|
| GET | `/api/admin/tenants` | `tenants:read` | List tenants |
| POST | `/api/admin/tenants` | `tenants:create` | Create tenant |

### API Keys

| Method | Endpoint | Permission | Description |
|--------|----------|------------|-------------|
| GET | `/api/admin/api-keys` | `api_keys:read` | List API keys |
| POST | `/api/admin/api-keys` | `api_keys:create` | Create API key |
| DELETE | `/api/admin/api-keys/:id` | `api_keys:delete` | Revoke API key |

### Audit & Stats

| Method | Endpoint | Permission | Description |
|--------|----------|------------|-------------|
| GET | `/api/admin/audit-logs` | `audit:read` | Paginated audit logs |
| GET | `/api/admin/stats` | `stats:read` | Dashboard statistics |

## OIDC Endpoints

### GET /.well-known/openid-configuration

OpenID Connect discovery document.

### GET /api/oidc/authorize

Authorization endpoint — redirects user to login, then back to client with auth code.

**Query Parameters:**

| Param | Description |
|-------|-------------|
| `response_type` | Must be `code` |
| `client_id` | API key ID |
| `redirect_uri` | Where to send the auth code |
| `scope` | `openid profile email` |
| `state` | CSRF protection value |

### POST /api/oidc/token

Exchange authorization code for tokens.

**Body:** `application/x-www-form-urlencoded`

| Param | Description |
|-------|-------------|
| `grant_type` | `authorization_code` |
| `code` | The authorization code |
| `redirect_uri` | Must match the authorize request |
| `client_id` | API key ID |
| `client_secret` | API key secret |

### GET /api/oidc/userinfo

Get user info for the authenticated user. Requires Bearer token.

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| Global | 100 req/min per IP |
| Login | 5 attempts / 15 min |
| Password Reset | 3 req/hour |
| API Key | Configurable per key (default 1000/hour) |

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Missing or invalid auth |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `RATE_LIMITED` | 429 | Too many requests |
| `ERROR` | 400 | General validation error |
