// Date: 2025-02-07
// Author: Alok
// File: src/auth.ts
// Purpose: Login, logout, refresh, password reset, email verification, first-time setup

import {
  Env, LoginRequest, LoginResponse, RegisterRequest,
  ResetPasswordRequest, VerifyEmailRequest, SetupRequest, User, Tenant
} from './types';
import { Database } from './db';
import { JWTService } from './jwt';
import { Utils } from './utils';

export class AuthService {
  private db: Database;
  private jwt: JWTService;
  private utils: Utils;

  constructor(private env: Env) {
    this.db = new Database(env);
    this.jwt = new JWTService(env);
    this.utils = new Utils(env);
  }

  async init(): Promise<void> { await this.jwt.init(); }

  // First-time setup — creates system tenant + admin user if no users exist
  async setup(req: SetupRequest, ipAddress: string): Promise<{ user: Partial<User>; tenant: Partial<Tenant> }> {
    const count = await this.db.countUsers();
    if (count > 0) throw new Error('System already initialized');

    if (!this.utils.validateEmail(req.email)) throw new Error('Invalid email');
    const pwErr = this.utils.validatePassword(req.password);
    if (pwErr) throw new Error(pwErr);

    // Create or use system tenant
    const slug = req.tenant_slug || 'system';
    const name = req.tenant_name || 'System Tenant';
    let tenant = await this.db.getTenantBySlug(slug);
    if (!tenant) tenant = await this.db.createTenant({ slug, name, settings: { features: ['all'] } });

    // Create admin user
    const hash = await this.utils.hashPassword(req.password);
    const user = await this.db.createUser({ email: req.email, password_hash: hash });
    await this.db.updateUser(user.id, { status: 'active', email_verified: true, email_verified_at: new Date().toISOString() } as any);
    await this.db.addUserToTenant(user.id, tenant.id, true);

    // Assign admin role
    const adminRole = await this.env.DB.prepare(
      `SELECT id FROM roles WHERE tenant_id = ? AND name = 'admin'`
    ).bind(tenant.id).first<{ id: number }>();
    if (adminRole) await this.db.assignRole(user.id, tenant.id, adminRole.id);

    await this.db.logAudit({ user_id: user.id, action: 'system_setup', ip_address: ipAddress, success: true });
    return {
      user: { id: user.id, email: user.email, status: 'active' },
      tenant: { id: tenant.id, name: tenant.name, slug: tenant.slug },
    };
  }

  async login(req: LoginRequest, ipAddress: string, userAgent: string): Promise<LoginResponse> {
    const { email, password, tenant_slug, remember_me } = req;
    if (!this.utils.validateEmail(email)) throw new Error('Invalid email format');

    let tenant: Tenant | null = null;
    if (tenant_slug) {
      tenant = await this.db.getTenantBySlug(tenant_slug);
      if (!tenant) throw new Error('Tenant not found');
      if (tenant.status === 'suspended') throw new Error('Tenant suspended');
    }

    // Rate limit
    const allowed = await this.db.checkRateLimit(`login:${ipAddress}`, 5, 900);
    if (!allowed) {
      await this.db.logAudit({ action: 'login_rate_limited', ip_address: ipAddress, user_agent: userAgent, success: false, error_message: 'Too many attempts' });
      throw new Error('Too many login attempts. Please try again later.');
    }

    const user = await this.db.getUserByEmail(email, tenant?.id);
    if (!user) {
      await this.db.logAudit({ action: 'login_failed', ip_address: ipAddress, user_agent: userAgent, success: false, error_message: 'User not found' });
      throw new Error('Invalid credentials');
    }

    if (user.status === 'locked') throw new Error(`Account locked: ${user.locked_reason || 'Contact support'}`);
    if (user.status === 'deleted') throw new Error('Account not found');

    const valid = await this.utils.verifyPassword(password, user.password_hash);
    if (!valid) {
      await this.db.updateUser(user.id, { failed_attempts: user.failed_attempts + 1, last_failed_at: new Date().toISOString() } as any);
      if (user.failed_attempts >= 4) {
        await this.db.updateUser(user.id, { status: 'locked', locked_at: new Date().toISOString(), locked_reason: 'Too many failed attempts' } as any);
      }
      await this.db.logAudit({ tenant_id: tenant?.id, user_id: user.id, action: 'login_failed', ip_address: ipAddress, user_agent: userAgent, success: false, error_message: 'Invalid password' });
      throw new Error('Invalid credentials');
    }

    if (user.failed_attempts > 0) await this.db.updateUser(user.id, { failed_attempts: 0 } as any);

    const roles = tenant ? await this.db.getUserRoles(user.id, tenant.id) : [];
    const permissions = roles.flatMap(r => r.permissions);

    const accessToken = await this.jwt.sign({
      sub: String(user.id), email: user.email,
      tid: tenant ? String(tenant.id) : undefined,
      roles: roles.map(r => r.name), permissions,
    });

    let refreshToken: string | undefined;
    if (remember_me) refreshToken = await this.jwt.createRefreshToken(user.id, tenant?.id);

    await this.db.logAudit({ tenant_id: tenant?.id, user_id: user.id, action: 'login', ip_address: ipAddress, user_agent: userAgent, success: true });

    // Webhook
    await this.utils.dispatchWebhook(tenant?.settings, {
      event: 'user.login', tenant_id: tenant?.id,
      data: { user_id: user.id, email: user.email }, timestamp: new Date().toISOString(),
    });

    return {
      success: true, access_token: accessToken, refresh_token: refreshToken, expires_in: 900,
      force_password_reset: !!user.force_password_reset,
      user: { id: user.id, email: user.email, email_verified: user.email_verified, status: user.status, metadata: user.metadata },
      tenant: tenant ? { id: tenant.id, name: tenant.name, slug: tenant.slug } : undefined,
    };
  }

  async register(req: RegisterRequest, ipAddress: string): Promise<User> {
    const { email, password, tenant_slug, metadata } = req;
    if (!this.utils.validateEmail(email)) throw new Error('Invalid email format');
    const pwErr = this.utils.validatePassword(password);
    if (pwErr) throw new Error(pwErr);

    const existing = await this.db.getUserByEmail(email);
    if (existing) throw new Error('Email already registered');

    let tenant: Tenant | null = null;
    if (tenant_slug) {
      tenant = await this.db.getTenantBySlug(tenant_slug);
      if (!tenant) throw new Error('Tenant not found');
      if (tenant.status !== 'active') throw new Error('Tenant not accepting registrations');
      // Check feature flag
      const features = tenant.settings?.features || [];
      if (features.length && !features.includes('all') && !features.includes('registration')) {
        throw new Error('Registration disabled for this tenant');
      }
    }

    const hash = await this.utils.hashPassword(password);
    const user = await this.db.createUser({ email, password_hash: hash, metadata: metadata || {} });

    if (tenant) {
      await this.db.addUserToTenant(user.id, tenant.id, true);
      const userRole = await this.env.DB.prepare(`SELECT id FROM roles WHERE tenant_id = ? AND name = 'user'`).bind(tenant.id).first<{ id: number }>();
      if (userRole) await this.db.assignRole(user.id, tenant.id, userRole.id);
    }

    const verifyToken = await this.db.createVerificationToken(user.id, 'email', 86400);
    try {
      await this.utils.sendEmail(email, 'Verify Your Email', this.utils.getEmailTemplate('verify', {
        link: `${this.env.APP_URL || 'https://yourdomain.com'}/verify?token=${verifyToken}`, expiry: 24,
      }));
    } catch (e) { console.error('Verification email failed:', e); }

    await this.db.logAudit({ tenant_id: tenant?.id, user_id: user.id, action: 'register', ip_address: ipAddress, success: true });
    await this.utils.dispatchWebhook(tenant?.settings, {
      event: 'user.registered', tenant_id: tenant?.id,
      data: { user_id: user.id, email }, timestamp: new Date().toISOString(),
    });
    return user;
  }

  async verifyEmail(req: VerifyEmailRequest): Promise<void> {
    const verification = await this.db.verifyToken(req.token, 'email');
    if (!verification) throw new Error('Invalid or expired token');
    await this.db.updateUser(verification.user_id, {
      email_verified: true, email_verified_at: new Date().toISOString(), status: 'active',
    } as any);
    await this.db.logAudit({ user_id: verification.user_id, action: 'email_verified', success: true });
  }

  async requestPasswordReset(email: string, ipAddress: string): Promise<void> {
    const allowed = await this.db.checkRateLimit(`reset:${ipAddress}`, 3, 3600);
    if (!allowed) throw new Error('Too many reset requests');
    const user = await this.db.getUserByEmail(email);
    if (!user) { await this.utils.sleep(1000); return; } // Prevent timing attack
    const token = await this.db.createVerificationToken(user.id, 'password', 3600);
    try {
      await this.utils.sendEmail(email, 'Reset Your Password', this.utils.getEmailTemplate('reset', {
        link: `${this.env.APP_URL || 'https://yourdomain.com'}/reset-password?token=${token}`, expiry: 1,
      }));
    } catch (e) { console.error('Reset email failed:', e); }
    await this.db.logAudit({ user_id: user.id, action: 'password_reset_requested', ip_address: ipAddress, success: true });
  }

  async resetPassword(req: ResetPasswordRequest): Promise<void> {
    const pwErr = this.utils.validatePassword(req.password);
    if (pwErr) throw new Error(pwErr);
    const verification = await this.db.verifyToken(req.token, 'password');
    if (!verification) throw new Error('Invalid or expired token');
    const hash = await this.utils.hashPassword(req.password);
    await this.db.updateUser(verification.user_id, {
      password_hash: hash, failed_attempts: 0, status: 'active',
      locked_at: null, locked_reason: null, force_password_reset: false,
    } as any);
    await this.env.DB.prepare(
      `UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = 'Password reset' WHERE user_id = ? AND revoked_at IS NULL`
    ).bind(verification.user_id).run();
    await this.db.logAudit({ user_id: verification.user_id, action: 'password_reset', success: true });
  }

  async refreshToken(refreshToken: string, ipAddress: string): Promise<LoginResponse> {
    const result = await this.jwt.rotateRefreshToken(refreshToken);
    const user = await this.db.getUserById(result.userId);
    if (!user) throw new Error('User not found');
    let tenant: Tenant | null = null;
    if (result.tenantId) tenant = await this.db.getTenantById(result.tenantId);
    await this.db.logAudit({ tenant_id: result.tenantId, user_id: result.userId, action: 'token_refreshed', ip_address: ipAddress, success: true });
    return {
      success: true, access_token: result.accessToken, refresh_token: result.refreshToken, expires_in: 900,
      user: { id: user.id, email: user.email, email_verified: user.email_verified, status: user.status },
      tenant: tenant ? { id: tenant.id, name: tenant.name, slug: tenant.slug } : undefined,
    };
  }

  async logout(token: string, userId: number): Promise<void> {
    await this.jwt.revokeToken(token);
    await this.env.DB.prepare(
      `UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = 'User logout' WHERE user_id = ? AND revoked_at IS NULL`
    ).bind(userId).run();
    await this.db.revokeAllUserSessions(userId);
    await this.db.logAudit({ user_id: userId, action: 'logout', success: true });
  }

  async changePassword(userId: number, currentPassword: string, newPassword: string): Promise<void> {
    const pwErr = this.utils.validatePassword(newPassword);
    if (pwErr) throw new Error(pwErr);
    const user = await this.db.getUserById(userId);
    if (!user) throw new Error('User not found');
    if (!await this.utils.verifyPassword(currentPassword, user.password_hash)) throw new Error('Current password is incorrect');
    const hash = await this.utils.hashPassword(newPassword);
    await this.db.updateUser(userId, { password_hash: hash, force_password_reset: false } as any);
    await this.env.DB.prepare(
      `UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = 'Password changed' WHERE user_id = ? AND revoked_at IS NULL`
    ).bind(userId).run();
    await this.db.logAudit({ user_id: userId, action: 'password_changed', success: true });
  }
}
