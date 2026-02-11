// Date: 2025-02-07
// Author: Alok
// File: src/db.ts
// Purpose: D1 queries, KV caching layer, batch operations

import {
  User, Tenant, Role, Session, ApiKey, VerificationToken,
  AuditLog, Env, PaginatedResponse, GDPRExportData
} from './types';
import { JWTService } from './jwt';
import { checkRateLimit as inMemoryRateLimit } from './rate-limiter';

// Reusable – copy to project reference
export class Database {
  constructor(private env: Env) {}

  // --- User operations ---
  async getUserById(id: number, useCache = true): Promise<User | null> {
    const cacheKey = `user:${id}`;
    if (useCache) {
      const cached = await this.env.CACHE.get(cacheKey, 'json') as User;
      if (cached) return cached;
    }
    const user = await this.env.DB.prepare(
      `SELECT * FROM users WHERE id = ? AND deleted_at IS NULL`
    ).bind(id).first<User>();
    if (user && useCache) {
      await this.env.CACHE.put(cacheKey, JSON.stringify(user), { expirationTtl: 3600 });
    }
    return user;
  }

  async getUserByEmail(email: string, tenantId?: number): Promise<User | null> {
    const cacheKey = `user:email:${email}:${tenantId || 'global'}`;
    const cached = await this.env.CACHE.get(cacheKey, 'json') as User;
    if (cached) return cached;

    const [query, params]: [string, any[]] = tenantId
      ? [`SELECT u.* FROM users u JOIN user_tenants ut ON u.id = ut.user_id
          WHERE u.email = ? AND ut.tenant_id = ? AND u.deleted_at IS NULL`, [email, tenantId]]
      : [`SELECT * FROM users WHERE email = ? AND deleted_at IS NULL`, [email]];

    const user = await this.env.DB.prepare(query).bind(...params).first<User>();
    if (user) await this.env.CACHE.put(cacheKey, JSON.stringify(user), { expirationTtl: 3600 });
    return user;
  }

  async createUser(data: { email: string; password_hash: string; metadata?: Record<string, any> }): Promise<User> {
    const result = await this.env.DB.prepare(
      `INSERT INTO users (email, password_hash, metadata) VALUES (?, ?, ?) RETURNING *`
    ).bind(data.email, data.password_hash, JSON.stringify(data.metadata || {})).first<User>();
    if (!result) throw new Error('Failed to create user');
    await this.env.CACHE.delete(`user:email:${data.email}:global`);
    return result;
  }

  async updateUser(id: number, updates: Partial<User>): Promise<User> {
    const sets: string[] = [];
    const values: any[] = [];
    Object.entries(updates).forEach(([key, value]) => {
      if (key !== 'id' && key !== 'created_at') {
        sets.push(`${key} = ?`);
        values.push(value === null ? null : typeof value === 'object' ? JSON.stringify(value) : value);
      }
    });
    if (sets.length === 0) throw new Error('No fields to update');
    values.push(id);
    const result = await this.env.DB.prepare(
      `UPDATE users SET ${sets.join(', ')} WHERE id = ? AND deleted_at IS NULL RETURNING *`
    ).bind(...values).first<User>();
    if (!result) throw new Error('User not found');
    await this.invalidateUserCache(id, result.email);
    return result;
  }

  async countUsers(): Promise<number> {
    const r = await this.env.DB.prepare(`SELECT COUNT(*) as c FROM users WHERE deleted_at IS NULL`).first<{c:number}>();
    return r?.c || 0;
  }

  // --- Tenant operations ---
  async getTenantBySlug(slug: string): Promise<Tenant | null> {
    const cacheKey = `tenant:slug:${slug}`;
    const cached = await this.env.CACHE.get(cacheKey, 'json') as Tenant;
    if (cached) return cached;
    const tenant = await this.env.DB.prepare(
      `SELECT * FROM tenants WHERE slug = ? AND status != 'deleted'`
    ).bind(slug).first<Tenant>();
    if (tenant) {
      tenant.settings = JSON.parse(tenant.settings as any || '{}');
      tenant.metadata = JSON.parse(tenant.metadata as any || '{}');
      await this.env.CACHE.put(cacheKey, JSON.stringify(tenant), { expirationTtl: 86400 });
    }
    return tenant;
  }

  async getTenantById(id: number): Promise<Tenant | null> {
    const tenant = await this.env.DB.prepare(`SELECT * FROM tenants WHERE id = ?`).bind(id).first<Tenant>();
    if (tenant) {
      tenant.settings = JSON.parse(tenant.settings as any || '{}');
      tenant.metadata = JSON.parse(tenant.metadata as any || '{}');
    }
    return tenant;
  }

  async createTenant(data: { slug: string; name: string; settings?: any }): Promise<Tenant> {
    const result = await this.env.DB.prepare(
      `INSERT INTO tenants (slug, name, settings) VALUES (?, ?, ?) RETURNING *`
    ).bind(data.slug, data.name, JSON.stringify(data.settings || {})).first<Tenant>();
    if (!result) throw new Error('Failed to create tenant');
    await this.createDefaultRoles(result.id);
    return result;
  }

  // --- Role operations ---
  async getUserRoles(userId: number, tenantId: number): Promise<Role[]> {
    const cacheKey = `roles:${userId}:${tenantId}`;
    const cached = await this.env.CACHE.get(cacheKey, 'json') as Role[];
    if (cached) return cached;

    const roles = await this.env.DB.prepare(`
      SELECT r.* FROM roles r JOIN user_roles ur ON r.id = ur.role_id
      WHERE ur.user_id = ? AND ur.tenant_id = ?
      AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
    `).bind(userId, tenantId).all<Role>();

    const parsed = roles.results.map(r => ({ ...r, permissions: JSON.parse(r.permissions as any || '[]') }));
    await this.env.CACHE.put(cacheKey, JSON.stringify(parsed), { expirationTtl: 3600 });
    return parsed;
  }

  async assignRole(userId: number, tenantId: number, roleId: number, grantedBy?: number): Promise<void> {
    await this.env.DB.prepare(
      `INSERT OR REPLACE INTO user_roles (user_id, tenant_id, role_id, granted_by) VALUES (?, ?, ?, ?)`
    ).bind(userId, tenantId, roleId, grantedBy ?? null).run();
    await this.env.CACHE.delete(`roles:${userId}:${tenantId}`);
  }

  private async createDefaultRoles(tenantId: number): Promise<void> {
    const roles = [
      { name: 'admin', permissions: ['*'], is_system: true },
      { name: 'user', permissions: ['read:own', 'update:own'], is_system: true },
      { name: 'readonly', permissions: ['read:*'], is_system: true },
    ];
    await this.env.DB.batch(roles.map(r =>
      this.env.DB.prepare(`INSERT INTO roles (tenant_id, name, permissions, is_system) VALUES (?, ?, ?, ?)`)
        .bind(tenantId, r.name, JSON.stringify(r.permissions), r.is_system)
    ));
  }

  // --- Session operations ---
  async createSession(userId: number, tenantId?: number, request?: Request, ttl = 86400): Promise<Session> {
    const id = crypto.randomUUID();
    const token = crypto.randomUUID();
    const jwtSvc = new JWTService(this.env);
    const tokenHash = await jwtSvc.sha256(token);
    const expires = new Date(Date.now() + ttl * 1000);
    const ip = request?.headers.get('CF-Connecting-IP') || null;
    const ua = request?.headers.get('User-Agent') || null;

    const session = await this.env.DB.prepare(
      `INSERT INTO sessions (id, user_id, tenant_id, token_hash, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING *`
    ).bind(id, userId, tenantId, tokenHash, ip, ua, expires.toISOString()).first<Session>();
    if (!session) throw new Error('Failed to create session');

    await this.env.SESSIONS.put(`session:${token}`, JSON.stringify({
      id: session.id, user_id: session.user_id, tenant_id: session.tenant_id
    }), { expirationTtl: ttl });
    return { ...session, token };
  }

  async getSession(token: string): Promise<Session | null> {
    const jwtSvc = new JWTService(this.env);
    const tokenHash = await jwtSvc.sha256(token);
    const cached = await this.env.SESSIONS.get(`session:${token}`, 'json') as Session;
    if (cached) return cached;
    const session = await this.env.DB.prepare(
      `SELECT * FROM sessions WHERE token_hash = ? AND expires_at > CURRENT_TIMESTAMP`
    ).bind(tokenHash).first<Session>();
    if (session) {
      await this.env.DB.prepare(`UPDATE sessions SET last_activity = CURRENT_TIMESTAMP WHERE id = ?`).bind(session.id).run();
    }
    return session;
  }

  // Get all active sessions for a user (admin: session/device management)
  async getUserSessions(userId: number): Promise<Session[]> {
    const r = await this.env.DB.prepare(
      `SELECT id, user_id, tenant_id, ip_address, user_agent, last_activity, expires_at, created_at FROM sessions WHERE user_id = ? AND expires_at > CURRENT_TIMESTAMP ORDER BY last_activity DESC`
    ).bind(userId).all<Session>();
    return r.results;
  }

  async revokeSession(sessionId: string): Promise<void> {
    await this.env.DB.prepare(`DELETE FROM sessions WHERE id = ?`).bind(sessionId).run();
  }

  async revokeAllUserSessions(userId: number): Promise<void> {
    await this.env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(userId).run();
  }

  // --- Verification tokens ---
  async createVerificationToken(userId: number, type: 'email' | 'password' | 'invite', ttl = 3600): Promise<string> {
    const id = crypto.randomUUID();
    const token = crypto.randomUUID();
    const jwtSvc = new JWTService(this.env);
    const tokenHash = await jwtSvc.sha256(token);
    const expires = new Date(Date.now() + ttl * 1000);
    await this.env.DB.prepare(
      `INSERT INTO verification_tokens (id, user_id, type, token_hash, expires_at) VALUES (?, ?, ?, ?, ?)`
    ).bind(id, userId, type, tokenHash, expires.toISOString()).run();
    return token;
  }

  async verifyToken(token: string, type: string): Promise<VerificationToken | null> {
    const jwtSvc = new JWTService(this.env);
    const tokenHash = await jwtSvc.sha256(token);
    const result = await this.env.DB.prepare(
      `SELECT * FROM verification_tokens WHERE token_hash = ? AND type = ? AND expires_at > CURRENT_TIMESTAMP AND used_at IS NULL`
    ).bind(tokenHash, type).first<VerificationToken>();
    if (result) {
      await this.env.DB.prepare(`UPDATE verification_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ?`).bind(result.id).run();
    }
    return result;
  }

  // --- API Key CRUD ---
  async createApiKey(tenantId: number, createdBy: number, data: {
    name: string; permissions?: string[]; expires_in_days?: number; ip_whitelist?: string[]; rate_limit?: number;
  }): Promise<{ apiKey: ApiKey; rawKey: string }> {
    const id = crypto.randomUUID();
    const prefix = `ak_${id.slice(0, 8)}`;
    const secret = Array.from(crypto.getRandomValues(new Uint8Array(32)),
      b => b.toString(16).padStart(2, '0')).join('');
    const rawKey = `${prefix}_${secret}`;
    const jwtSvc = new JWTService(this.env);
    const keyHash = await jwtSvc.sha256(rawKey);
    const expires = data.expires_in_days
      ? new Date(Date.now() + data.expires_in_days * 86400000).toISOString() : null;

    const apiKey = await this.env.DB.prepare(`
      INSERT INTO api_keys (id, tenant_id, name, key_hash, permissions, expires_at, created_by, ip_whitelist, rate_limit)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *
    `).bind(id, tenantId, data.name, keyHash, JSON.stringify(data.permissions || []),
      expires, createdBy, JSON.stringify(data.ip_whitelist || []), data.rate_limit || 1000
    ).first<ApiKey>();
    if (!apiKey) throw new Error('Failed to create API key');
    return { apiKey: { ...apiKey, key_prefix: prefix }, rawKey };
  }

  async listApiKeys(tenantId: number): Promise<ApiKey[]> {
    const r = await this.env.DB.prepare(
      `SELECT id, tenant_id, name, permissions, last_used_at, expires_at, created_at, created_by, revoked_at, ip_whitelist, rate_limit
       FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC`
    ).bind(tenantId).all<ApiKey>();
    return r.results.map(k => ({ ...k, permissions: JSON.parse(k.permissions as any || '[]') }));
  }

  async revokeApiKey(keyId: string, tenantId: number): Promise<void> {
    await this.env.DB.prepare(
      `UPDATE api_keys SET revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND tenant_id = ?`
    ).bind(keyId, tenantId).run();
  }

  // --- Audit logging ---
  async logAudit(data: {
    tenant_id?: number; user_id?: number; action: string; resource_type?: string;
    resource_id?: string; changes?: any; ip_address?: string; user_agent?: string;
    success?: boolean; error_message?: string;
  }): Promise<void> {
    await this.env.DB.prepare(`
      INSERT INTO audit_logs (tenant_id, user_id, action, resource_type, resource_id, changes, ip_address, user_agent, success, error_message)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      data.tenant_id ?? null, data.user_id ?? null, data.action, data.resource_type ?? null,
      data.resource_id ?? null, data.changes ? JSON.stringify(data.changes) : null,
      data.ip_address ?? null, data.user_agent ?? null, data.success ?? true, data.error_message ?? null
    ).run();
  }

  // --- Rate limiting (in-memory, zero KV writes) ---
  // Moved from KV to in-memory to avoid exhausting KV put() daily limits.
  // KV was doing 1 put per request for rate limiting alone — the #1 cause of limit exhaustion.
  // In-memory counters reset when the Worker isolate is evicted, which is acceptable
  // for rate limiting (brief resets are better than hitting KV write quotas).
  checkRateLimit(key: string, limit: number, window: number): boolean {
    return inMemoryRateLimit(key, limit, window).allowed;
  }

  // --- User-tenant operations ---
  async addUserToTenant(userId: number, tenantId: number, isPrimary = false): Promise<void> {
    await this.env.DB.prepare(
      `INSERT INTO user_tenants (user_id, tenant_id, is_primary) VALUES (?, ?, ?)
       ON CONFLICT(user_id, tenant_id) DO UPDATE SET is_primary = excluded.is_primary`
    ).bind(userId, tenantId, isPrimary).run();
    const user = await this.getUserById(userId, false);
    if (user) await this.invalidateUserCache(userId, user.email);
  }

  // --- GDPR data export ---
  async exportUserData(userId: number): Promise<GDPRExportData> {
    const user = await this.getUserById(userId, false);
    if (!user) throw new Error('User not found');

    const tenants = await this.env.DB.prepare(
      `SELECT t.* FROM tenants t JOIN user_tenants ut ON t.id = ut.tenant_id WHERE ut.user_id = ?`
    ).bind(userId).all<Tenant>();

    const rolesData: { tenant: string; roles: string[] }[] = [];
    for (const t of tenants.results) {
      const roles = await this.getUserRoles(userId, t.id);
      rolesData.push({ tenant: t.name, roles: roles.map(r => r.name) });
    }

    const sessions = await this.getUserSessions(userId);
    const logs = await this.env.DB.prepare(
      `SELECT action, ip_address, created_at, success FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 500`
    ).bind(userId).all<AuditLog>();

    const { password_hash, ...safeUser } = user;
    return {
      user: safeUser,
      tenants: tenants.results.map(({ settings, metadata, ...t }) => t),
      roles: rolesData,
      sessions: sessions.map(({ token_hash, ...s }) => s),
      audit_logs: logs.results,
    };
  }

  // --- Pagination helper ---
  async paginate<T>(query: string, params: any[], page = 1, limit = 20): Promise<PaginatedResponse<T>> {
    const offset = (page - 1) * limit;
    const countQuery = query.replace(/SELECT .* FROM/, 'SELECT COUNT(*) as count FROM').replace(/ORDER BY .*/, '');
    const { count } = await this.env.DB.prepare(countQuery).bind(...params).first<{ count: number }>() || { count: 0 };
    const results = await this.env.DB.prepare(`${query} LIMIT ? OFFSET ?`).bind(...params, limit, offset).all<T>();
    return { items: results.results, total: count, page, pages: Math.ceil(count / limit), limit };
  }

  // FIXED: invalidates all known cache keys for a user including tenant-scoped
  private async invalidateUserCache(userId: number, email?: string): Promise<void> {
    await this.env.CACHE.delete(`user:${userId}`);
    if (email) {
      await this.env.CACHE.delete(`user:email:${email}:global`);
      // Clear tenant-scoped caches — query all tenants user belongs to
      const tenants = await this.env.DB.prepare(
        `SELECT tenant_id FROM user_tenants WHERE user_id = ?`
      ).bind(userId).all<{ tenant_id: number }>();
      await Promise.all(tenants.results.map(t =>
        Promise.all([
          this.env.CACHE.delete(`user:email:${email}:${t.tenant_id}`),
          this.env.CACHE.delete(`roles:${userId}:${t.tenant_id}`),
        ])
      ));
    }
  }
}
