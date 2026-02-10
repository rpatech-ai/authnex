// Date: 2026-02-09
// File: src/signup.ts
// Purpose: Self-service tenant signup, plan selection, API key generation

import { Env, Tenant, User } from './types';
import { Database } from './db';
import { JWTService } from './jwt';
import { Utils } from './utils';

export interface SignupRequest {
  email: string;
  password: string;
  company_name: string;
  tenant_slug: string;
  plan?: string;
}

export interface SignupResponse {
  user: Partial<User>;
  tenant: Partial<Tenant>;
  api_key: string;
  access_token: string;
  refresh_token: string;
}

export class SignupService {
  private db: Database;
  private jwt: JWTService;
  private utils: Utils;

  constructor(private env: Env) {
    this.db = new Database(env);
    this.jwt = new JWTService(env);
    this.utils = new Utils(env);
  }

  async init(): Promise<void> { await this.jwt.init(); }

  async selfServiceSignup(req: SignupRequest, ipAddress: string, userAgent: string): Promise<SignupResponse> {
    // Validate input
    if (!this.utils.validateEmail(req.email)) throw new Error('Invalid email format');
    const pwErr = this.utils.validatePassword(req.password);
    if (pwErr) throw new Error(pwErr);
    if (!req.company_name?.trim()) throw new Error('Company name is required');
    if (!req.tenant_slug?.trim()) throw new Error('Tenant slug is required');
    if (!/^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$/.test(req.tenant_slug)) {
      throw new Error('Slug: 3-50 chars, lowercase, numbers, hyphens, must start/end with alphanumeric');
    }

    // Check uniqueness
    const existingUser = await this.db.getUserByEmail(req.email);
    if (existingUser) throw new Error('Email already registered');
    const existingTenant = await this.db.getTenantBySlug(req.tenant_slug);
    if (existingTenant) throw new Error('Tenant slug already taken');

    // Resolve plan
    const planName = req.plan || 'free';
    const plan = await this.env.DB.prepare(
      `SELECT * FROM plans WHERE name = ? AND is_active = 1`
    ).bind(planName).first<any>();
    if (!plan) throw new Error('Invalid plan');

    // Create tenant
    const tenant = await this.db.createTenant({
      slug: req.tenant_slug,
      name: req.company_name,
      settings: { features: JSON.parse(plan.features || '[]') },
    });

    // Set tenant plan
    await this.env.DB.prepare(`UPDATE tenants SET plan = ? WHERE id = ?`).bind(planName, tenant.id).run();

    // Create billing record
    const trialEnd = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000); // 14-day trial
    await this.env.DB.prepare(`
      INSERT INTO billing_status (tenant_id, plan_id, status, trial_ends_at, current_period_start, current_period_end)
      VALUES (?, ?, 'trial', ?, CURRENT_TIMESTAMP, ?)
    `).bind(tenant.id, plan.id, trialEnd.toISOString(), trialEnd.toISOString()).run();

    // Create admin user
    const hash = await this.utils.hashPassword(req.password);
    const user = await this.db.createUser({ email: req.email, password_hash: hash });
    await this.db.updateUser(user.id, { status: 'active', email_verified: false } as any);
    await this.db.addUserToTenant(user.id, tenant.id, true);

    // Assign admin role
    const adminRole = await this.env.DB.prepare(
      `SELECT id FROM roles WHERE tenant_id = ? AND name = 'admin'`
    ).bind(tenant.id).first<{ id: number }>();
    if (adminRole) await this.db.assignRole(user.id, tenant.id, adminRole.id);

    // Generate API key
    const apiKeyResult = await this.db.createApiKey(tenant.id, user.id, {
      name: 'Default API Key',
      permissions: ['*'],
      expires_in_days: 365,
    });

    // Generate tokens
    const accessToken = await this.jwt.sign({
      sub: String(user.id),
      email: user.email,
      tid: String(tenant.id),
      roles: ['admin'],
      permissions: ['*'],
    });
    const refreshToken = await this.jwt.createRefreshToken(user.id, tenant.id);

    // Send verification email
    try {
      const verifyToken = await this.db.createVerificationToken(user.id, 'email', 86400);
      await this.utils.sendEmail(req.email, 'Verify Your Email — Welcome to AuthNex', this.utils.getEmailTemplate('verify', {
        link: `${this.env.APP_URL || 'https://authnex.com'}/verify?token=${verifyToken}`,
        expiry: 24,
      }));
    } catch (e) { console.error('Verification email failed:', e); }

    // Initialize usage tracking
    const period = new Date().toISOString().slice(0, 7); // YYYY-MM
    await this.env.DB.prepare(
      `INSERT OR IGNORE INTO usage_tracking (tenant_id, period) VALUES (?, ?)`
    ).bind(tenant.id, period).run();

    // Audit log
    await this.db.logAudit({
      tenant_id: tenant.id, user_id: user.id,
      action: 'self_service_signup', ip_address: ipAddress,
      user_agent: userAgent, success: true,
    });

    return {
      user: { id: user.id, email: user.email, status: 'active' },
      tenant: { id: tenant.id, name: tenant.name, slug: tenant.slug, plan: planName },
      api_key: apiKeyResult.rawKey,
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  async getPlans(): Promise<any[]> {
    const plans = await this.env.DB.prepare(
      `SELECT id, name, display_name, max_users, max_api_calls, features, price_monthly, price_yearly FROM plans WHERE is_active = 1 ORDER BY price_monthly ASC`
    ).all<any>();
    return plans.results.map(p => ({ ...p, features: JSON.parse(p.features || '[]') }));
  }

  async checkSlugAvailability(slug: string): Promise<boolean> {
    const tenant = await this.db.getTenantBySlug(slug);
    return !tenant;
  }
}
