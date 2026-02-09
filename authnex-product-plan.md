# AuthNex — Product Readiness Plan & Customer Journey

**Date:** 2026-02-08
**Author:** Alok
**Status:** Phase 1 Complete → Product Wrapper Needed

---

## 1. Current State Summary

### What's Built & Working (Phase 1)

| Layer | Status | Detail |
|-------|--------|--------|
| Auth API (Workers + D1) | ✅ Production | Login, register, JWT RS256, refresh rotation, password reset, email verify |
| Multi-Tenancy | ✅ Production | Tenant isolation, tenant-scoped RBAC, cross-tenant users |
| Admin Dashboard | ✅ Production | Users, roles, tenants, API keys, audit logs, settings |
| Security | ✅ Production | Brute force, rate limiting, CSRF, CORS, audit logging |
| Token Management | ✅ Production | JWKS endpoint, blacklist, API keys for M2M |
| GDPR | ✅ Production | Data export (admin + self-service), bulk export |
| Webhooks | ✅ Production | HMAC-signed, fire-and-forget on key events |

### What's NOT Built Yet

| Feature | Priority | Impact |
|---------|----------|--------|
| PHP SDK | P0 | Target market can't integrate easily |
| JS SDK | P0 | No frontend helper at all |
| Login Widget | P0 | Customer builds own login form |
| Self-service Tenant Signup | P1 | You onboard every customer manually |
| Documentation Site | P1 | No quick-start, no API reference |
| OIDC Endpoints | P2 | Can't use standard OAuth libraries |
| Social Login (Google/MS) | P2 | No SSO option for end-users |
| Customer Dashboard | P3 | Customer uses your super-admin or nothing |
| 2FA / TOTP | P3 | No second factor |
| WebAuthn / Passkeys | P3 | No passwordless |

---

## 2. Customer Journey — Today (Manual) vs Target (Self-Service)

### Today: Manual Onboarding

```
Customer contacts you
    ↓
You create tenant in admin dashboard
    ↓
You give them: API URL + tenant_slug
    ↓
Customer writes raw HTTP calls (fetch/cURL/PHP)
    ↓
Customer builds own login form
    ↓
Customer fetches JWKS, verifies JWT manually
    ↓
Customer builds own session middleware
    ↓
Customer builds own role-checking logic
```

**Problem:** ~2-5 days integration work for the customer. High friction. No docs.

### Target: Self-Service Onboarding

```
Customer visits authnex.com → signs up → gets tenant + API key instantly
    ↓
Follows quick-start: "Add auth to your PHP app in 5 minutes"
    ↓
composer require authnex/php-sdk
    ↓
3 lines in PHP: init SDK → protect routes → done
    ↓
Drops <script src="widget.js"> into HTML → login form appears
    ↓
Users register/login → tokens handled automatically
    ↓
Customer manages users via their dashboard or API
```

**Goal:** 5-minute integration. Zero calls to you.

---

## 3. Development Roadmap — File Generation Plan

### Sprint 1: PHP SDK (P0) — ~5 files

Makes your platform usable for PHP developers immediately.

| File | Purpose | Lines (est) |
|------|---------|-------------|
| `sdk/php/src/AuthNex.php` | Main SDK class — init, login, register, verify, protect | ~200 |
| `sdk/php/src/TokenVerifier.php` | JWKS fetch, RS256 verify, claim validation, cache | ~120 |
| `sdk/php/src/Middleware.php` | Drop-in session middleware — auto-refresh, role check | ~80 |
| `sdk/php/src/Exceptions.php` | AuthNexException, TokenExpired, Unauthorized | ~30 |
| `sdk/php/composer.json` | Package definition, autoload, dependencies (guzzle, firebase/jwt) | ~25 |

**Customer usage after Sprint 1:**

```php
require 'vendor/autoload.php';
$auth = new AuthNex(['api_url' => '...', 'tenant' => '...', 'api_key' => '...']);

// Protect any page
$auth->protect();              // redirects to login if no session
$user = $auth->getUser();      // current user
$auth->requireRole('admin');   // throws if not admin

// Or use as middleware
$auth->middleware()->handle($request);
```

---

### Sprint 2: JS Login Widget (P0) — ~4 files

Drop-in login/register UI. No customer-side form building.

| File | Purpose | Lines (est) |
|------|---------|-------------|
| `sdk/js/src/widget.ts` | Login/register form, token storage, auto-refresh, events | ~300 |
| `sdk/js/src/api-client.ts` | Typed HTTP client — login, register, refresh, profile | ~120 |
| `sdk/js/src/styles.css` | Widget styling, responsive, light/dark theme | ~150 |
| `sdk/js/rollup.config.js` | Bundle to single `authnex-widget.min.js` for CDN | ~20 |

**Customer usage after Sprint 2:**

```html
<script src="https://cdn.authnex.com/widget.min.js"></script>
<div id="authnex-login" data-tenant="acme-corp"></div>
<script>
  AuthNex.init({ container: '#authnex-login', apiUrl: 'https://auth.yourdomain.com' });
  AuthNex.onLogin(user => console.log('Logged in:', user));
</script>
```

---

### Sprint 3: Self-Service Signup & Customer Dashboard (P1) — ~6 files

Customers sign up, get a tenant, manage their users — without you.

| File | Purpose | Lines (est) |
|------|---------|-------------|
| `src/signup.ts` | New Worker routes: tenant signup, plan selection, API key generation | ~150 |
| `customer-portal/index.html` | Customer dashboard SPA — users, roles, API keys, usage | ~400 |
| `customer-portal/api.js` | API client for customer-scoped endpoints | ~100 |
| `customer-portal/styles.css` | Portal styling | ~80 |
| `schema-v2.sql` | Migration: plans table, usage_tracking, billing_status | ~40 |
| `src/billing.ts` | Usage metering, plan limits enforcement | ~100 |

**New API Endpoints:**

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/signup` | Create tenant + admin user + API key (self-service) |
| GET | `/api/portal/dashboard` | Customer's own stats |
| GET | `/api/portal/users` | Customer manages their users |
| GET | `/api/portal/usage` | API call counts, limits |

---

### Sprint 4: Documentation Site (P1) — ~5 files

Without docs, no one can integrate.

| File | Purpose | Lines (est) |
|------|---------|-------------|
| `docs/index.html` | Landing + navigation | ~100 |
| `docs/quickstart.md` | 5-minute PHP integration guide | ~80 |
| `docs/api-reference.md` | All endpoints, request/response, examples | ~300 |
| `docs/widget-guide.md` | JS widget setup, events, customization | ~100 |
| `docs/concepts.md` | Tenants, roles, tokens, JWKS explained | ~120 |

---

### Sprint 5: OIDC + Social Login (P2) — ~4 files

Standard protocol support. Google/Microsoft login buttons.

| File | Purpose | Lines (est) |
|------|---------|-------------|
| `src/oidc.ts` | `/.well-known/openid-configuration`, `/authorize`, `/token`, `/userinfo` | ~250 |
| `src/social.ts` | Google/Microsoft OAuth2 flows, account linking | ~200 |
| `schema-v3.sql` | Migration: social_accounts table | ~20 |
| `sdk/js/src/social-buttons.ts` | "Sign in with Google" button component | ~80 |

---

### Sprint 6: 2FA + Passkeys (P3) — ~3 files

| File | Purpose | Lines (est) |
|------|---------|-------------|
| `src/totp.ts` | TOTP setup, verify, backup codes | ~150 |
| `src/webauthn.ts` | Registration, authentication ceremonies | ~200 |
| `schema-v4.sql` | Migration: totp_secrets, webauthn_credentials | ~25 |

---

## 4. Sprint Timeline

| Sprint | What | Duration | Outcome |
|--------|------|----------|---------|
| 1 | PHP SDK | 3-4 days | PHP devs can integrate via `composer require` |
| 2 | JS Widget | 3-4 days | Drop-in login form for any website |
| 3 | Self-Service + Portal | 5-7 days | Customers sign up without you |
| 4 | Documentation | 2-3 days | Quick-start + API reference |
| 5 | OIDC + Social | 5-7 days | Google/MS login, standard protocol |
| 6 | 2FA + Passkeys | 4-5 days | Second factor, passwordless |

**MVP (Sprints 1-4):** ~2-3 weeks → product is sellable
**Full Product (All 6):** ~5-6 weeks

---

## 5. File Tree — Full Product (After All Sprints)

```
auth-platform/
├── src/                          ← Backend (existing + new)
│   ├── index.ts                  ← Add new routes for signup, portal, OIDC
│   ├── auth.ts                   ← Existing
│   ├── admin.ts                  ← Existing
│   ├── db.ts                     ← Existing
│   ├── jwt.ts                    ← Existing
│   ├── middleware.ts             ← Existing
│   ├── types.ts                  ← Extend with new types
│   ├── utils.ts                  ← Existing
│   ├── signup.ts                 ← NEW: self-service tenant creation
│   ├── billing.ts                ← NEW: usage metering, plan limits
│   ├── oidc.ts                   ← NEW: OIDC endpoints
│   ├── social.ts                 ← NEW: Google/MS OAuth
│   ├── totp.ts                   ← NEW: 2FA
│   └── webauthn.ts               ← NEW: passkeys
│
├── sdk/
│   ├── php/
│   │   ├── composer.json
│   │   └── src/
│   │       ├── AuthNex.php       ← NEW: main SDK
│   │       ├── TokenVerifier.php ← NEW: JWT verification
│   │       ├── Middleware.php    ← NEW: session middleware
│   │       └── Exceptions.php   ← NEW: exception classes
│   │
│   └── js/
│       ├── rollup.config.js
│       └── src/
│           ├── widget.ts         ← NEW: login widget
│           ├── api-client.ts     ← NEW: HTTP client
│           ├── social-buttons.ts ← NEW: Google/MS buttons
│           └── styles.css        ← NEW: widget styles
│
├── admin/                        ← Your super-admin (existing)
│   ├── login.html
│   ├── index.html
│   ├── api.js
│   └── styles.css
│
├── customer-portal/              ← NEW: customer's own dashboard
│   ├── index.html
│   ├── api.js
│   └── styles.css
│
├── docs/                         ← NEW: documentation
│   ├── index.html
│   ├── quickstart.md
│   ├── api-reference.md
│   ├── widget-guide.md
│   └── concepts.md
│
├── schema.sql                    ← Existing base
├── schema-v2.sql                 ← NEW: plans, usage, billing
├── schema-v3.sql                 ← NEW: social_accounts
├── schema-v4.sql                 ← NEW: totp, webauthn
├── wrangler.json
├── package.json
├── tsconfig.json
└── README.md
```

---

## 
