// Date: 2025-02-07
// Author: Alok
// File: src/admin.ts
// Purpose: Admin API endpoints for user/tenant/apikey management, GDPR, sessions

import { Env, AuthContext, User, Tenant, Role, PaginatedResponse, ApiKeyCreateRequest, GDPRExportData } from './types';
import { Database } from './db';
import { Utils } from './utils';
import { Middleware } from './middleware';

export class AdminService {
  private db: Database;
  private utils: Utils;
  private middleware: Middleware;

  constructor(private env: Env) {
    this.db = new Database(env);
    this.utils = new Utils(env);
    this.middleware = new Middleware(env);
  }

  // --- User management ---
  async listUsers(ctx: AuthContext, params: { page?: number; limit?: number; search?: string; status?: string }): Promise<PaginatedResponse<User>> {
    this.middleware.requirePermission(ctx, 'users:read');
    let query = `SELECT * FROM users WHERE deleted_at IS NULL`;
    const qp: any[] = [];
    if (ctx.tenant && !this.middleware.hasPermission(ctx, '*')) {
      query = `SELECT u.* FROM users u JOIN user_tenants ut ON u.id = ut.user_id WHERE u.deleted_at IS NULL AND ut.tenant_id = ?`;
      qp.push(ctx.tenant.id);
    }
    if (params.search) { query += ` AND email LIKE ?`; qp.push(`%${params.search}%`); }
    if (params.status) { query += ` AND status = ?`; qp.push(params.status); }
    query += ` ORDER BY created_at DESC`;
    return this.db.paginate<User>(query, qp, params.page, params.limit);
  }

  async getUser(ctx: AuthContext, userId: number): Promise<User> {
    this.middleware.requirePermission(ctx, 'users:read');
    const user = await this.db.getUserById(userId);
    if (!user) throw new Error('User not found');
    if (ctx.tenant && !this.middleware.hasPermission(ctx, '*')) {
      const access = await this.env.DB.prepare(`SELECT 1 FROM user_tenants WHERE user_id = ? AND tenant_id = ?`).bind(userId, ctx.tenant.id).first();
      if (!access) throw new Error('User not in tenant');
    }
    return user;
  }

  async createUser(ctx: AuthContext, data: { email: string; password: string; status?: string; roles?: number[]; metadata?: any }): Promise<User> {
    this.middleware.requirePermission(ctx, 'users:create');
    if (!this.utils.validateEmail(data.email)) throw new Error('Invalid email');
    const pwErr = this.utils.validatePassword(data.password);
    if (pwErr) throw new Error(pwErr);
    const existing = await this.db.getUserByEmail(data.email);
    if (existing) throw new Error('Email already exists');

    const hash = await this.utils.hashPassword(data.password);
    const user = await this.db.createUser({ email: data.email, password_hash: hash, metadata: data.metadata || {} });
    if (data.status) await this.db.updateUser(user.id, { status: data.status } as any);

    if (ctx.tenant) {
      await this.db.addUserToTenant(user.id, ctx.tenant.id, true);
      if (data.roles?.length) {
        for (const rid of data.roles) await this.db.assignRole(user.id, ctx.tenant.id, rid, ctx.user?.id);
      }
    }

    try {
      await this.utils.sendEmail(data.email, 'Welcome!', this.utils.getEmailTemplate('welcome', {
        email: data.email, tenantName: ctx.tenant?.name, loginUrl: `${this.env.APP_URL || 'https://yourdomain.com'}/login`,
      }));
    } catch (e) { console.error('Welcome email failed:', e); }

    await this.db.logAudit({ tenant_id: ctx.tenant?.id, user_id: ctx.user?.id, action: 'user_created', resource_type: 'user', resource_id: String(user.id), success: true });
    return user;
  }

  async updateUser(ctx: AuthContext, userId: number, updates: Partial<User>): Promise<User> {
    this.middleware.requirePermission(ctx, 'users:update');
    delete updates.id; delete updates.password_hash; delete updates.created_at;
    const user = await this.db.updateUser(userId, updates);
    await this.db.logAudit({ tenant_id: ctx.tenant?.id, user_id: ctx.user?.id, action: 'user_updated', resource_type: 'user', resource_id: String(userId), changes: updates, success: true });
    return user;
  }

  async deleteUser(ctx: AuthContext, userId: number): Promise<void> {
    this.middleware.requirePermission(ctx, 'users:delete');
    await this.db.updateUser(userId, { status: 'deleted', deleted_at: new Date().toISOString() } as any);
    await this.env.DB.prepare(`UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = 'User deleted' WHERE user_id = ?`).bind(userId).run();
    await this.db.logAudit({ tenant_id: ctx.tenant?.id, user_id: ctx.user?.id, action: 'user_deleted', resource_type: 'user', resource_id: String(userId), success: true });
  }

  async lockUser(ctx: AuthContext, userId: number, reason: string): Promise<void> {
    this.middleware.requirePermission(ctx, 'users:update');
    await this.db.updateUser(userId, { status: 'locked', locked_at: new Date().toISOString(), locked_by: ctx.user?.id, locked_reason: reason } as any);
    await this.db.logAudit({ tenant_id: ctx.tenant?.id, user_id: ctx.user?.id, action: 'user_locked', resource_type: 'user', resource_id: String(userId), changes: { reason }, success: true });
  }

  async unlockUser(ctx: AuthContext, userId: number): Promise<void> {
    this.middleware.requirePermission(ctx, 'users:update');
    await this.db.updateUser(userId, { status: 'active', locked_at: null, locked_by: null, locked_reason: null, failed_attempts: 0 } as any);
    await this.db.logAudit({ tenant_id: ctx.tenant?.id, user_id: ctx.user?.id, action: 'user_unlocked', resource_type: 'user', resource_id: String(userId), success: true });
  }

  // Force user to change password on next login
  async forcePasswordReset(ctx: AuthContext, userId: number): Promise<void> {
    this.middleware.requirePermission(ctx, 'users:update');
    await this.db.updateUser(userId, { force_password_reset: true } as any);
    await this.env.DB.prepare(`UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = 'Forced reset' WHERE user_id = ? AND revoked_at IS NULL`).bind(userId).run();
    await this.db.logAudit({ tenant_id: ctx.tenant?.id, user_id: ctx.user?.id, action: 'force_password_reset', resource_type: 'user', resource_id: String(userId), success: true });
  }

  // --- Session/device management ---
  async getUserSessions(ctx: AuthContext, userId: number): Promise<any[]> {
    this.middleware.requirePermission(ctx, 'users:read');
    return this.db.getUserSessions(userId);
  }

  async revokeUserSession(ctx: AuthContext, userId: number, sessionId: string): Promise<void> {
    this.middleware.requirePermission(ctx, 'users:update');
    await this.db.revokeSession(sessionId);
    await this.db.logAudit({ tenant_id: ctx.tenant?.id, user_id: ctx.user?.id, action: 'session_revoked', resource_type: 'session', resource_id: sessionId, success: true });
  }

  // --- Role management ---
  async listRoles(ctx: AuthContext): Promise<Role[]> {
    this.middleware.requirePermission(ctx, 'roles:read');
    if (!ctx.tenant) throw new Error('Tenant required');
    const roles = await this.env.DB.prepare(`SELECT * FROM roles WHERE tenant_id = ?`).bind(ctx.tenant.id).all<Role>();
    return roles.results.map(r => ({ ...r, permissions: JSON.parse(r.permissions as any || '[]') }));
  }

  async createRole(ctx: AuthContext, data: { name: string; permissions: string[] }): Promise<Role> {
    this.middleware.requirePermission(ctx, 'roles:create');
    if (!ctx.tenant) throw new Error('Tenant required');
    const result = await this.env.DB.prepare(
      `INSERT INTO roles (tenant_id, name, permissions) VALUES (?, ?, ?) RETURNING *`
    ).bind(ctx.tenant.id, data.name, JSON.stringify(data.permissions)).first<Role>();
    if (!result) throw new Error('Failed to create role');
    await this.db.logAudit({ tenant_id: ctx.tenant.id, user_id: ctx.user?.id, action: 'role_created', resource_type: 'role', resource_id: String(result.id), success: true });
    return { ...result, permissions: data.permissions };
  }

  async assignUserRole(ctx: AuthContext, userId: number, roleId: number): Promise<void> {
    this.middleware.requirePermission(ctx, 'users:update');
    if (!ctx.tenant) throw new Error('Tenant required');
    await this.db.assignRole(userId, ctx.tenant.id, roleId, ctx.user?.id);
    await this.db.logAudit({ tenant_id: ctx.tenant.id, user_id: ctx.user?.id, action: 'role_assigned', resource_type: 'user', resource_id: String(userId), changes: { role_id: roleId }, success: true });
  }

  async removeUserRole(ctx: AuthContext, userId: number, roleId: number): Promise<void> {
    this.middleware.requirePermission(ctx, 'users:update');
    if (!ctx.tenant) throw new Error('Tenant required');
    await this.env.DB.prepare(`DELETE FROM user_roles WHERE user_id = ? AND tenant_id = ? AND role_id = ?`).bind(userId, ctx.tenant.id, roleId).run();
    await this.env.CACHE.delete(`roles:${userId}:${ctx.tenant.id}`);
    await this.db.logAudit({ tenant_id: ctx.tenant.id, user_id: ctx.user?.id, action: 'role_removed', resource_type: 'user', resource_id: String(userId), changes: { role_id: roleId }, success: true });
  }

  // --- Tenant management ---
  async listTenants(ctx: AuthContext): Promise<Tenant[]> {
    this.middleware.requirePermission(ctx, 'tenants:read');
    const tenants = await this.env.DB.prepare(`SELECT * FROM tenants WHERE status != 'deleted'`).all<Tenant>();
    return tenants.results.map(t => ({ ...t, settings: JSON.parse(t.settings as any || '{}'), metadata: JSON.parse(t.metadata as any || '{}') }));
  }

  async createTenant(ctx: AuthContext, data: { slug: string; name: string; settings?: any }): Promise<Tenant> {
    this.middleware.requirePermission(ctx, 'tenants:create');
    if (!/^[a-z0-9-]+$/.test(data.slug)) throw new Error('Slug: lowercase, numbers, hyphens only');
    const tenant = await this.db.createTenant(data);
    await this.db.logAudit({ user_id: ctx.user?.id, action: 'tenant_created', resource_type: 'tenant', resource_id: String(tenant.id), success: true });
    return tenant;
  }

  // --- API Key CRUD ---
  async listApiKeys(ctx: AuthContext): Promise<any[]> {
    this.middleware.requirePermission(ctx, 'api_keys:read');
    if (!ctx.tenant) throw new Error('Tenant required');
    return this.db.listApiKeys(ctx.tenant.id);
  }

  async createApiKey(ctx: AuthContext, data: ApiKeyCreateRequest): Promise<any> {
    this.middleware.requirePermission(ctx, 'api_keys:create');
    if (!ctx.tenant || !ctx.user) throw new Error('Tenant and user required');
    const result = await this.db.createApiKey(ctx.tenant.id, ctx.user.id, data);
    await this.db.logAudit({ tenant_id: ctx.tenant.id, user_id: ctx.user.id, action: 'api_key_created', resource_type: 'api_key', resource_id: result.apiKey.id, success: true });
    return result;
  }

  async revokeApiKey(ctx: AuthContext, keyId: string): Promise<void> {
    this.middleware.requirePermission(ctx, 'api_keys:delete');
    if (!ctx.tenant) throw new Error('Tenant required');
    await this.db.revokeApiKey(keyId, ctx.tenant.id);
    await this.db.logAudit({ tenant_id: ctx.tenant.id, user_id: ctx.user?.id, action: 'api_key_revoked', resource_type: 'api_key', resource_id: keyId, success: true });
  }

  // --- Audit logs ---
  async getAuditLogs(ctx: AuthContext, params: { page?: number; limit?: number; user_id?: number; action?: string; from?: string; to?: string }): Promise<PaginatedResponse<any>> {
    this.middleware.requirePermission(ctx, 'audit:read');
    let query = `SELECT * FROM audit_logs WHERE 1=1`;
    const qp: any[] = [];
    if (ctx.tenant && !this.middleware.hasPermission(ctx, '*')) { query += ` AND tenant_id = ?`; qp.push(ctx.tenant.id); }
    if (params.user_id) { query += ` AND user_id = ?`; qp.push(params.user_id); }
    if (params.action) { query += ` AND action = ?`; qp.push(params.action); }
    if (params.from) { query += ` AND created_at >= ?`; qp.push(params.from); }
    if (params.to) { query += ` AND created_at <= ?`; qp.push(params.to); }
    query += ` ORDER BY created_at DESC`;
    return this.db.paginate(query, qp, params.page, params.limit);
  }

  // --- Stats ---
  async getStats(ctx: AuthContext): Promise<any> {
    this.middleware.requirePermission(ctx, 'stats:read');
    const stats: any = {};
    if (ctx.tenant) {
      const [users, active, logins] = await Promise.all([
        this.env.DB.prepare(`SELECT COUNT(*) as c FROM user_tenants WHERE tenant_id = ?`).bind(ctx.tenant.id).first<{c:number}>(),
        this.env.DB.prepare(`SELECT COUNT(DISTINCT user_id) as c FROM audit_logs WHERE tenant_id = ? AND created_at > datetime('now','-30 days')`).bind(ctx.tenant.id).first<{c:number}>(),
        this.env.DB.prepare(`SELECT COUNT(*) as c FROM audit_logs WHERE tenant_id = ? AND action = 'login' AND created_at > datetime('now','-30 days')`).bind(ctx.tenant.id).first<{c:number}>(),
      ]);
      stats.users = users?.c || 0; stats.activeUsers = active?.c || 0; stats.logins = logins?.c || 0;
    } else {
      const [users, tenants] = await Promise.all([
        this.env.DB.prepare(`SELECT COUNT(*) as c FROM users WHERE deleted_at IS NULL`).first<{c:number}>(),
        this.env.DB.prepare(`SELECT COUNT(*) as c FROM tenants WHERE status = 'active'`).first<{c:number}>(),
      ]);
      stats.users = users?.c || 0; stats.tenants = tenants?.c || 0;
    }
    return stats;
  }

  // --- GDPR export ---
  async exportUserData(ctx: AuthContext, userId: number): Promise<GDPRExportData> {
    this.middleware.requirePermission(ctx, 'users:read');
    return this.db.exportUserData(userId);
  }

  // --- Bulk operations ---
  async bulkImportUsers(ctx: AuthContext, users: any[]): Promise<{ imported: number; failed: number; errors: string[] }> {
    this.middleware.requirePermission(ctx, 'users:create');
    let imported = 0, failed = 0;
    const errors: string[] = [];
    for (const u of users) {
      try { await this.createUser(ctx, u); imported++; }
      catch (e: any) { failed++; errors.push(`${u.email}: ${e.message}`); }
    }
    await this.db.logAudit({ tenant_id: ctx.tenant?.id, user_id: ctx.user?.id, action: 'bulk_import', changes: { imported, failed }, success: true });
    return { imported, failed, errors };
  }

  async bulkExportUsers(ctx: AuthContext, params: { status?: string }): Promise<Partial<User>[]> {
    this.middleware.requirePermission(ctx, 'users:read');
    let query = `SELECT id, email, status, email_verified, created_at, metadata FROM users WHERE deleted_at IS NULL`;
    const qp: any[] = [];
    if (ctx.tenant && !this.middleware.hasPermission(ctx, '*')) {
      query = `SELECT u.id, u.email, u.status, u.email_verified, u.created_at, u.metadata FROM users u JOIN user_tenants ut ON u.id = ut.user_id WHERE u.deleted_at IS NULL AND ut.tenant_id = ?`;
      qp.push(ctx.tenant.id);
    }
    if (params.status) { query += ` AND status = ?`; qp.push(params.status); }
    query += ` ORDER BY created_at DESC LIMIT 10000`;
    const r = await this.env.DB.prepare(query).bind(...qp).all<Partial<User>>();
    return r.results;
  }
}
