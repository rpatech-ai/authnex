// Date: 2026-02-09
// File: src/billing.ts
// Purpose: Usage metering, plan limits enforcement, portal stats

import { Env, AuthContext, Tenant } from './types';
import { Database } from './db';
import { Middleware } from './middleware';

export class BillingService {
  private db: Database;
  private middleware: Middleware;

  constructor(private env: Env) {
    this.db = new Database(env);
    this.middleware = new Middleware(env);
  }

  // Track an API call for a tenant
  async trackUsage(tenantId: number, metric: 'api_calls' | 'logins' | 'registrations' | 'token_refreshes'): Promise<void> {
    const period = new Date().toISOString().slice(0, 7); // YYYY-MM
    await this.env.DB.prepare(`
      INSERT INTO usage_tracking (tenant_id, period, ${metric}) VALUES (?, ?, 1)
      ON CONFLICT(tenant_id, period) DO UPDATE SET ${metric} = ${metric} + 1, updated_at = CURRENT_TIMESTAMP
    `).bind(tenantId, period).run();
  }

  // Check if tenant is within plan limits
  async checkLimits(tenantId: number): Promise<{ allowed: boolean; reason?: string }> {
    const billing = await this.env.DB.prepare(`
      SELECT b.*, p.max_users, p.max_api_calls, p.name as plan_name
      FROM billing_status b JOIN plans p ON b.plan_id = p.id
      WHERE b.tenant_id = ?
    `).bind(tenantId).first<any>();

    if (!billing) return { allowed: true }; // No billing record = no limits

    // Check trial expiry
    if (billing.status === 'trial' && new Date(billing.trial_ends_at) < new Date()) {
      return { allowed: false, reason: 'Trial period expired. Please upgrade your plan.' };
    }

    if (billing.status === 'cancelled') {
      return { allowed: false, reason: 'Subscription cancelled.' };
    }

    // Check user limit (-1 means unlimited)
    if (billing.max_users > 0) {
      const userCount = await this.env.DB.prepare(
        `SELECT COUNT(*) as c FROM user_tenants WHERE tenant_id = ?`
      ).bind(tenantId).first<{ c: number }>();
      if ((userCount?.c || 0) >= billing.max_users) {
        return { allowed: false, reason: `User limit reached (${billing.max_users}). Please upgrade.` };
      }
    }

    // Check API call limit
    if (billing.max_api_calls > 0) {
      const period = new Date().toISOString().slice(0, 7);
      const usage = await this.env.DB.prepare(
        `SELECT api_calls FROM usage_tracking WHERE tenant_id = ? AND period = ?`
      ).bind(tenantId, period).first<{ api_calls: number }>();
      if ((usage?.api_calls || 0) >= billing.max_api_calls) {
        return { allowed: false, reason: `API call limit reached (${billing.max_api_calls}/month). Please upgrade.` };
      }
    }

    return { allowed: true };
  }

  // Get portal dashboard stats for a tenant owner
  async getPortalDashboard(ctx: AuthContext): Promise<any> {
    if (!ctx.tenant) throw new Error('Tenant required');
    const tenantId = ctx.tenant.id;

    const period = new Date().toISOString().slice(0, 7);
    const [userCount, usage, billing, recentLogins] = await Promise.all([
      this.env.DB.prepare(`SELECT COUNT(*) as c FROM user_tenants WHERE tenant_id = ?`).bind(tenantId).first<{ c: number }>(),
      this.env.DB.prepare(`SELECT * FROM usage_tracking WHERE tenant_id = ? AND period = ?`).bind(tenantId, period).first<any>(),
      this.env.DB.prepare(`
        SELECT b.*, p.name as plan_name, p.display_name as plan_display, p.max_users, p.max_api_calls
        FROM billing_status b JOIN plans p ON b.plan_id = p.id WHERE b.tenant_id = ?
      `).bind(tenantId).first<any>(),
      this.env.DB.prepare(`
        SELECT COUNT(*) as c FROM audit_logs WHERE tenant_id = ? AND action = 'login' AND created_at > datetime('now', '-30 days')
      `).bind(tenantId).first<{ c: number }>(),
    ]);

    return {
      users: { total: userCount?.c || 0, limit: billing?.max_users || 0 },
      usage: {
        api_calls: usage?.api_calls || 0,
        logins: usage?.logins || 0,
        registrations: usage?.registrations || 0,
        limit: billing?.max_api_calls || 0,
        period,
      },
      plan: {
        name: billing?.plan_name || 'free',
        display_name: billing?.plan_display || 'Free',
        status: billing?.status || 'active',
        trial_ends_at: billing?.trial_ends_at,
      },
      recent_logins_30d: recentLogins?.c || 0,
    };
  }

  // Get usage history for chart display
  async getUsageHistory(tenantId: number, months = 6): Promise<any[]> {
    const results = await this.env.DB.prepare(`
      SELECT period, api_calls, logins, registrations, token_refreshes
      FROM usage_tracking WHERE tenant_id = ? ORDER BY period DESC LIMIT ?
    `).bind(tenantId, months).all<any>();
    return results.results;
  }

  // List tenant's users (for customer portal)
  async getPortalUsers(ctx: AuthContext, params: { page?: number; limit?: number; search?: string }): Promise<any> {
    if (!ctx.tenant) throw new Error('Tenant required');
    let query = `SELECT u.id, u.email, u.status, u.email_verified, u.created_at, u.metadata
      FROM users u JOIN user_tenants ut ON u.id = ut.user_id
      WHERE ut.tenant_id = ? AND u.deleted_at IS NULL`;
    const qp: any[] = [ctx.tenant.id];

    if (params.search) { query += ` AND u.email LIKE ?`; qp.push(`%${params.search}%`); }
    query += ` ORDER BY u.created_at DESC`;

    return this.db.paginate(query, qp, params.page || 1, params.limit || 20);
  }

  // Get API usage stats per endpoint
  async getPortalApiUsage(ctx: AuthContext): Promise<any> {
    if (!ctx.tenant) throw new Error('Tenant required');
    const period = new Date().toISOString().slice(0, 7);
    const usage = await this.env.DB.prepare(
      `SELECT * FROM usage_tracking WHERE tenant_id = ? AND period = ?`
    ).bind(ctx.tenant.id, period).first<any>();
    return usage || { api_calls: 0, logins: 0, registrations: 0, token_refreshes: 0, period };
  }
}
