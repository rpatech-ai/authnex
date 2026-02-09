// Date: 2026-02-09
// File: src/social.ts
// Purpose: Google/Microsoft OAuth2 flows, account linking

import { Env, User } from './types';
import { Database } from './db';
import { JWTService } from './jwt';
import { Utils } from './utils';

interface SocialProviderConfig {
  clientId: string;
  clientSecret: string;
  authUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  scopes: string[];
}

const PROVIDERS: Record<string, Omit<SocialProviderConfig, 'clientId' | 'clientSecret'>> = {
  google: {
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://www.googleapis.com/oauth2/v3/userinfo',
    scopes: ['openid', 'email', 'profile'],
  },
  microsoft: {
    authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
    scopes: ['openid', 'email', 'profile', 'User.Read'],
  },
  github: {
    authUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    userInfoUrl: 'https://api.github.com/user',
    scopes: ['user:email'],
  },
};

export class SocialAuthService {
  private db: Database;
  private jwt: JWTService;
  private utils: Utils;

  constructor(private env: Env) {
    this.db = new Database(env);
    this.jwt = new JWTService(env);
    this.utils = new Utils(env);
  }

  async init(): Promise<void> { await this.jwt.init(); }

  // Get the OAuth2 authorization URL for a provider
  getAuthorizationUrl(provider: string, tenantSlug: string, redirectUri: string, state?: string): string {
    const config = this.getProviderConfig(provider);
    const params = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: config.scopes.join(' '),
      state: state || this.generateState(tenantSlug),
      access_type: 'offline',
      prompt: 'select_account',
    });
    return `${config.authUrl}?${params.toString()}`;
  }

  // Handle the OAuth2 callback — exchange code, get profile, login/register
  async handleCallback(
    provider: string, code: string, redirectUri: string, tenantSlug: string, ipAddress: string, userAgent: string
  ): Promise<{
    access_token: string; refresh_token: string; expires_in: number;
    user: Partial<User>; is_new_user: boolean;
  }> {
    const config = this.getProviderConfig(provider);

    // Exchange code for tokens
    const tokenResponse = await fetch(config.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: config.clientId,
        client_secret: config.clientSecret,
      }).toString(),
    });

    if (!tokenResponse.ok) {
      const error = await tokenResponse.text();
      throw new Error(`OAuth token exchange failed: ${error}`);
    }

    const tokens = await tokenResponse.json() as any;

    // Get user profile from provider
    const profile = await this.getUserProfile(provider, tokens.access_token, config.userInfoUrl);

    if (!profile.email) {
      throw new Error('Email not available from social provider');
    }

    // Resolve tenant
    const tenant = await this.db.getTenantBySlug(tenantSlug);
    if (!tenant) throw new Error('Tenant not found');
    if (tenant.status !== 'active') throw new Error('Tenant not active');

    // Check if social account exists
    const existingSocial = await this.env.DB.prepare(
      `SELECT * FROM social_accounts WHERE provider = ? AND provider_user_id = ?`
    ).bind(provider, profile.id).first<any>();

    let user: User;
    let isNewUser = false;

    if (existingSocial) {
      // Existing social account — get linked user
      const linkedUser = await this.db.getUserById(existingSocial.user_id);
      if (!linkedUser) throw new Error('Linked user not found');
      if (linkedUser.status === 'locked') throw new Error('Account locked');
      if (linkedUser.status === 'deleted') throw new Error('Account not found');
      user = linkedUser;

      // Update social tokens
      await this.env.DB.prepare(`
        UPDATE social_accounts SET access_token = ?, refresh_token = ?,
        token_expires_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
      `).bind(
        tokens.access_token, tokens.refresh_token || null,
        tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000).toISOString() : null,
        existingSocial.id
      ).run();
    } else {
      // Check if user exists by email
      const existingUser = await this.db.getUserByEmail(profile.email, tenant.id);

      if (existingUser) {
        // Link social account to existing user
        user = existingUser;
        await this.createSocialAccount(user.id, provider, profile, tokens);
      } else {
        // Create new user
        const randomPassword = crypto.randomUUID() + 'Aa1!'; // Social users don't use password
        const hash = await this.utils.hashPassword(randomPassword);
        user = await this.db.createUser({
          email: profile.email,
          password_hash: hash,
          metadata: { name: profile.name, avatar: profile.avatar, social_provider: provider },
        });
        await this.db.updateUser(user.id, {
          status: 'active', email_verified: true, email_verified_at: new Date().toISOString(),
        } as any);
        await this.db.addUserToTenant(user.id, tenant.id, true);

        // Assign default user role
        const userRole = await this.env.DB.prepare(
          `SELECT id FROM roles WHERE tenant_id = ? AND name = 'user'`
        ).bind(tenant.id).first<{ id: number }>();
        if (userRole) await this.db.assignRole(user.id, tenant.id, userRole.id);

        await this.createSocialAccount(user.id, provider, profile, tokens);
        isNewUser = true;
      }
    }

    // Generate AuthNex tokens
    const roles = await this.db.getUserRoles(user.id, tenant.id);
    const permissions = roles.flatMap(r => r.permissions);

    const accessToken = await this.jwt.sign({
      sub: String(user.id), email: user.email,
      tid: String(tenant.id),
      roles: roles.map(r => r.name), permissions,
    });
    const refreshToken = await this.jwt.createRefreshToken(user.id, tenant.id);

    // Audit log
    await this.db.logAudit({
      tenant_id: tenant.id, user_id: user.id,
      action: isNewUser ? 'social_register' : 'social_login',
      ip_address: ipAddress, user_agent: userAgent,
      changes: { provider }, success: true,
    });

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 900,
      user: { id: user.id, email: user.email, status: user.status, metadata: user.metadata },
      is_new_user: isNewUser,
    };
  }

  // List social accounts linked to a user
  async getLinkedAccounts(userId: number): Promise<any[]> {
    const result = await this.env.DB.prepare(
      `SELECT id, provider, email, name, avatar_url, created_at FROM social_accounts WHERE user_id = ?`
    ).bind(userId).all<any>();
    return result.results;
  }

  // Unlink a social account
  async unlinkAccount(userId: number, accountId: number): Promise<void> {
    // Ensure user has at least a password or another social account
    const accounts = await this.env.DB.prepare(
      `SELECT COUNT(*) as c FROM social_accounts WHERE user_id = ?`
    ).bind(userId).first<{ c: number }>();

    if ((accounts?.c || 0) <= 1) {
      // Check if user has a real password (not auto-generated for social)
      const user = await this.db.getUserById(userId);
      if (user?.metadata && (user.metadata as any).social_provider) {
        throw new Error('Cannot unlink the only authentication method. Set a password first.');
      }
    }

    await this.env.DB.prepare(
      `DELETE FROM social_accounts WHERE id = ? AND user_id = ?`
    ).bind(accountId, userId).run();
  }

  // --- Internal ---

  private getProviderConfig(provider: string): SocialProviderConfig {
    const base = PROVIDERS[provider];
    if (!base) throw new Error(`Unsupported provider: ${provider}`);

    // Read client credentials from env
    const prefix = provider.toUpperCase();
    const clientId = (this.env as any)[`${prefix}_CLIENT_ID`];
    const clientSecret = (this.env as any)[`${prefix}_CLIENT_SECRET`];

    if (!clientId || !clientSecret) {
      throw new Error(`${provider} OAuth not configured. Set ${prefix}_CLIENT_ID and ${prefix}_CLIENT_SECRET.`);
    }

    return { ...base, clientId, clientSecret };
  }

  private async getUserProfile(provider: string, accessToken: string, userInfoUrl: string): Promise<{
    id: string; email: string; name?: string; avatar?: string;
  }> {
    const headers: Record<string, string> = { 'Authorization': `Bearer ${accessToken}` };
    if (provider === 'github') headers['Accept'] = 'application/json';

    const response = await fetch(userInfoUrl, { headers });
    if (!response.ok) throw new Error(`Failed to fetch profile from ${provider}`);
    const data = await response.json() as any;

    switch (provider) {
      case 'google':
        return { id: data.sub, email: data.email, name: data.name, avatar: data.picture };
      case 'microsoft':
        return { id: data.id, email: data.mail || data.userPrincipalName, name: data.displayName };
      case 'github':
        // GitHub may need separate email API call
        let email = data.email;
        if (!email) {
          const emailResp = await fetch('https://api.github.com/user/emails', {
            headers: { 'Authorization': `Bearer ${accessToken}`, 'Accept': 'application/json' },
          });
          const emails = await emailResp.json() as any[];
          const primary = emails.find((e: any) => e.primary && e.verified);
          email = primary?.email || emails[0]?.email;
        }
        return { id: String(data.id), email, name: data.name || data.login, avatar: data.avatar_url };
      default:
        throw new Error(`Unknown provider: ${provider}`);
    }
  }

  private async createSocialAccount(userId: number, provider: string, profile: any, tokens: any): Promise<void> {
    await this.env.DB.prepare(`
      INSERT INTO social_accounts (user_id, provider, provider_user_id, email, name, avatar_url, access_token, refresh_token, token_expires_at, raw_profile)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      userId, provider, profile.id, profile.email, profile.name || null, profile.avatar || null,
      tokens.access_token, tokens.refresh_token || null,
      tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000).toISOString() : null,
      JSON.stringify(profile)
    ).run();
  }

  private generateState(tenantSlug: string): string {
    const random = crypto.randomUUID();
    return btoa(JSON.stringify({ tenant: tenantSlug, nonce: random }));
  }
}
