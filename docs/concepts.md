# Core Concepts

Understanding how AuthNex works under the hood.

## Tenants

A **tenant** is an isolated workspace in AuthNex. Each customer gets their own tenant with:

- Unique slug (e.g., `acme-corp`)
- Separate user pool
- Independent roles and permissions
- Own API keys
- Usage tracking and billing

Users can belong to multiple tenants (cross-tenant support), but each user has a primary tenant.

### Tenant Status

| Status | Meaning |
|--------|---------|
| `active` | Fully operational |
| `trial` | In free trial period |
| `suspended` | Admin-suspended, auth calls blocked |

## Users

Users are identified by email (unique globally). Each user has:

- **Status**: `active`, `pending` (unverified), `locked`, `deleted`
- **Email verification**: Required for full access
- **Password hash**: PBKDF2-SHA256, 100K iterations
- **Metadata**: Flexible JSON field for custom data

### User Lifecycle

```
Register → pending (email unverified)
    ↓
Verify email → active
    ↓
Failed logins (5x) → locked
    ↓
Admin unlock → active
    ↓
Admin delete → deleted (soft delete)
```

## Roles & Permissions

AuthNex uses **Role-Based Access Control (RBAC)** scoped to each tenant.

### Default Roles

Every tenant gets three system roles:

| Role | Permissions | Purpose |
|------|-------------|---------|
| `admin` | `*` (all) | Full access |
| `user` | `read:own`, `update:own` | Standard user |
| `readonly` | `read:*` | View-only access |

### Custom Roles

Create roles with specific permissions:

```json
{
  "name": "editor",
  "permissions": ["articles:read", "articles:create", "articles:update"]
}
```

### Permission Format

Permissions follow the pattern: `resource:action`

- `users:read` — Read user data
- `users:create` — Create users
- `*` — Wildcard (all permissions)
- `users:*` — All actions on users resource

## Tokens

AuthNex uses a dual-token system:

### Access Token (JWT)

- **Algorithm**: RS256 (RSA-PKCS1-v1_5 with SHA-256)
- **Expiry**: 15 minutes
- **Contains**: user ID, email, tenant ID, roles, permissions
- **Verified via**: Public key (JWKS endpoint)

### Refresh Token

- **Expiry**: 7 days
- **Stored as**: SHA-256 hash in database
- **Rotation**: New refresh token issued on each use
- **Family tracking**: Detects token reuse (stolen token protection)

### Token Flow

```
Login → access_token + refresh_token
    ↓
API calls → send access_token in Authorization header
    ↓
Token expired → POST /api/auth/refresh with refresh_token
    ↓
New access_token + new refresh_token (old one revoked)
```

## JWKS (JSON Web Key Set)

The public key for verifying JWTs is available at:

```
GET /api/auth/jwks
```

SDKs automatically fetch and cache this key. The response contains the RSA public key in JWK format with:
- `kid`: Key ID (`primary`)
- `alg`: Algorithm (`RS256`)
- `use`: Usage (`sig`)

## API Keys

For machine-to-machine (M2M) authentication:

- Sent via `X-API-Key` header
- Scoped to a tenant
- Have their own permissions
- Support IP whitelisting
- Per-key rate limiting
- Stored as SHA-256 hash (raw key shown once)

## Webhooks

AuthNex dispatches webhooks on key events:

| Event | When |
|-------|------|
| `user.login` | User logs in |
| `user.registered` | New user registers |
| `user.locked` | Account locked |
| `user.deleted` | Account deleted |

Webhooks are:
- HMAC-SHA256 signed (via `X-Webhook-Signature` header)
- Fire-and-forget (non-blocking)
- Configurable per tenant in settings

## Audit Logging

Every authentication event is logged:

- Login attempts (success/fail)
- Registration
- Password changes/resets
- Token refreshes
- Admin actions (user CRUD, role changes)
- API key operations

Logs are retained for 90 days and accessible via the admin API.

## Rate Limiting

- Per IP + endpoint (sliding window)
- Login: 5 attempts per 15 minutes
- Password reset: 3 requests per hour
- API: Per-key configurable limits
- Global: 100 requests per minute per IP
