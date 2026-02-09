// Date: 2025-02-07
// Author: Alok
// File: src/middleware.ts
// Purpose: Auth check, CORS, tenant isolation, rate limit, CSRF, security headers

import { Env, AuthContext, Tenant } from './types';
import { JWTService } from './jwt';
import { Database } from './db';
import { Utils } from './utils';
import { checkRateLimit } from './rate-limiter';

export class Middleware {
  private jwt: JWTService;
  private db: Database;
  private utils: Utils;

  constructor(private env: Env) {
    this.jwt = new JWTService(env);
    this.db = new Database(env);
    this.utils = new Utils(env);
  }

  async init(): Promise<void> { await this.jwt.init(); }

  // CORS preflight
  cors(request: Request): Response | null {
    if (request.method !== 'OPTIONS') return null;
    const origin = request.headers.get('Origin');
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': origin || '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token, X-Tenant-Slug, X-API-Key',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400',
      },
    });
  }

  addCorsHeaders(response: Response, request: Request): Response {
    const res = new Response(response.body, response);
    res.headers.set('Access-Control-Allow-Origin', request.headers.get('Origin') || '*');
    res.headers.set('Access-Control-Allow-Credentials', 'true');
    res.headers.set('Vary', 'Origin');
    return res;
  }

  rateLimit(request: Request, limits: { requests: number; window: number }): Response | null {
    const ip = this.utils.getClientIP(request);
    // Rate limit per IP globally (not per-path) to reduce key cardinality
    const result = checkRateLimit(`global:${ip}`, limits.requests, limits.window);
    if (!result.allowed) {
      const retryAfter = Math.ceil((result.resetAt - Date.now()) / 1000);
      return new Response(JSON.stringify({
        success: false,
        error: { code: 'RATE_LIMITED', message: 'Too many requests. Please try again later.', timestamp: new Date().toISOString() },
      }), {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(retryAfter),
          'X-RateLimit-Limit': String(limits.requests),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': String(Math.ceil(result.resetAt / 1000)),
        },
      });
    }
    return null;
  }

  // FIXED: token stored in context.token instead of immutable request.headers
  async authenticate(request: Request, required = true): Promise<AuthContext> {
    const context: AuthContext = {};
    const authHeader = request.headers.get('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      if (required) throw new Error('No authorization token provided');
      return context;
    }

    const token = authHeader.substring(7);
    try {
      const payload = await this.jwt.verify(token);
      const user = await this.db.getUserById(parseInt(payload.sub));
      if (!user) throw new Error('User not found');
      if (user.status !== 'active') throw new Error('User account not active');

      context.user = user;
      context.token = token; // Store for potential revocation

      if (payload.tid) {
        const tenant = await this.db.getTenantById(parseInt(payload.tid));
        if (tenant) {
          context.tenant = tenant;
          context.roles = await this.db.getUserRoles(user.id, tenant.id);
          context.permissions = context.roles.flatMap(r => r.permissions);
        }
      }
      return context;
    } catch (error: any) {
      if (required) throw new Error(`Authentication failed: ${error.message}`);
      return context;
    }
  }

  async requireTenant(request: Request, context: AuthContext): Promise<Tenant> {
    if (context.tenant) return context.tenant;
    const slug = request.headers.get('X-Tenant-Slug') || new URL(request.url).searchParams.get('tenant');
    if (!slug) throw new Error('Tenant not specified');
    const tenant = await this.db.getTenantBySlug(slug);
    if (!tenant) throw new Error('Tenant not found');
    if (tenant.status !== 'active') throw new Error('Tenant not active');

    if (context.user) {
      const access = await this.env.DB.prepare(
        `SELECT 1 FROM user_tenants WHERE user_id = ? AND tenant_id = ?`
      ).bind(context.user.id, tenant.id).first();
      if (!access) throw new Error('Access denied to tenant');
      // Load roles for this tenant
      context.roles = await this.db.getUserRoles(context.user.id, tenant.id);
      context.permissions = context.roles.flatMap(r => r.permissions);
    }
    context.tenant = tenant;
    return tenant;
  }

  // Tenant feature flag check
  checkFeature(context: AuthContext, feature: string): boolean {
    const features = context.tenant?.settings?.features || [];
    return features.includes('all') || features.includes(feature);
  }

  requireFeature(context: AuthContext, feature: string): void {
    if (!this.checkFeature(context, feature)) throw new Error(`Feature '${feature}' not enabled`);
  }

  hasPermission(context: AuthContext, permission: string): boolean {
    if (!context.permissions) return false;
    if (context.permissions.includes('*')) return true;
    if (context.permissions.includes(permission)) return true;
    const [resource] = permission.split(':');
    return context.permissions.includes(`${resource}:*`);
  }

  requirePermission(context: AuthContext, permission: string): void {
    if (!this.hasPermission(context, permission)) throw new Error(`Missing permission: ${permission}`);
  }

  // CSRF validation — call for state-changing requests
  async validateCSRF(request: Request): Promise<void> {
    if (['GET', 'HEAD', 'OPTIONS'].includes(request.method)) return;
    // Skip CSRF for API-key or Bearer-token authenticated requests (stateless)
    if (request.headers.get('Authorization')?.startsWith('Bearer ')) return;
    if (request.headers.get('X-API-Key')) return;

    const token = request.headers.get('X-CSRF-Token');
    if (!token) throw new Error('CSRF token missing');
    const cookies = this.parseCookies(request.headers.get('Cookie') || '');
    if (!cookies['csrf_token'] || !this.utils.verifyCSRFToken(token, cookies['csrf_token'])) {
      throw new Error('Invalid CSRF token');
    }
  }

  // API key authentication
  async authenticateApiKey(request: Request): Promise<AuthContext> {
    const apiKey = request.headers.get('X-API-Key');
    if (!apiKey) throw new Error('API key required');

    const jwtSvc = new JWTService(this.env);
    const keyHash = await jwtSvc.sha256(apiKey);

    const key = await this.env.DB.prepare(
      `SELECT * FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`
    ).bind(keyHash).first<any>();
    if (!key) throw new Error('Invalid API key');

    // IP whitelist check
    if (key.ip_whitelist) {
      const whitelist = JSON.parse(key.ip_whitelist);
      if (whitelist.length > 0 && !whitelist.includes(this.utils.getClientIP(request))) {
        throw new Error('IP not whitelisted');
      }
    }

    const allowed = await this.db.checkRateLimit(`api:${key.id}`, key.rate_limit, 3600);
    if (!allowed) throw new Error('API rate limit exceeded');

    await this.env.DB.prepare(`UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?`).bind(key.id).run();

    const tenant = await this.db.getTenantById(key.tenant_id);
    if (!tenant) throw new Error('Tenant not found');
    return { tenant, permissions: JSON.parse(key.permissions || '[]') };
  }

  addSecurityHeaders(response: Response): Response {
    const res = new Response(response.body, response);
    res.headers.set('X-Content-Type-Options', 'nosniff');
    res.headers.set('X-Frame-Options', 'DENY');
    res.headers.set('X-XSS-Protection', '1; mode=block');
    res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.headers.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    if (this.env.ENVIRONMENT === 'production') {
      res.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
      res.headers.set('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;");
    }
    return res;
  }

  private parseCookies(header: string): Record<string, string> {
    const cookies: Record<string, string> = {};
    header.split(';').forEach(c => {
      const [name, value] = c.trim().split('=');
      if (name && value) cookies[name] = decodeURIComponent(value);
    });
    return cookies;
  }

  handleError(error: any, request: Request): Response {
    const isDev = this.env.ENVIRONMENT === 'development';
    const status = error.message?.includes('not found') ? 404
      : error.message?.includes('Authentication') || error.message?.includes('Unauthorized') ? 401
      : error.message?.includes('permission') || error.message?.includes('Access denied') ? 403
      : error.message?.includes('Rate') || error.message?.includes('Too many') ? 429
      : 400;

    return new Response(JSON.stringify({
      success: false,
      error: {
        code: error.code || 'ERROR',
        message: isDev ? error.message : (status >= 500 ? 'An error occurred' : error.message),
        timestamp: new Date().toISOString(),
        ...(isDev && { stack: error.stack }),
      },
    }), { status, headers: { 'Content-Type': 'application/json' } });
  }
}
