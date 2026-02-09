// Date: 2026-02-09
// File: src/oidc.ts
// Purpose: OpenID Connect endpoints — discovery, authorize, token, userinfo

import { Env, AuthContext } from './types';
import { Database } from './db';
import { JWTService } from './jwt';
import { Middleware } from './middleware';
import { Utils } from './utils';

export class OIDCService {
  private db: Database;
  private jwt: JWTService;
  private middleware: Middleware;
  private utils: Utils;

  constructor(private env: Env) {
    this.db = new Database(env);
    this.jwt = new JWTService(env);
    this.middleware = new Middleware(env);
    this.utils = new Utils(env);
  }

  async init(): Promise<void> { await this.jwt.init(); }

  // OpenID Connect Discovery Document
  getDiscovery(baseUrl: string): any {
    return {
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/api/oidc/authorize`,
      token_endpoint: `${baseUrl}/api/oidc/token`,
      userinfo_endpoint: `${baseUrl}/api/oidc/userinfo`,
      jwks_uri: `${baseUrl}/api/auth/jwks`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: ['openid', 'profile', 'email'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
      claims_supported: ['sub', 'email', 'email_verified', 'name', 'iat', 'exp', 'iss', 'aud'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
    };
  }

  // Authorization endpoint — validates params and redirects to login or generates code
  async authorize(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const params = Object.fromEntries(url.searchParams);
    const { response_type, client_id, redirect_uri, scope, state } = params;

    // Validate required params
    if (response_type !== 'code') {
      return this.errorRedirect(redirect_uri, 'unsupported_response_type', 'Only code flow supported', state);
    }
    if (!client_id) {
      return this.errorRedirect(redirect_uri, 'invalid_request', 'client_id required', state);
    }
    if (!redirect_uri) {
      return this.utils.errorResponse('redirect_uri required', 'INVALID_REQUEST', 400);
    }

    // Validate client (API key)
    const keyHash = await this.jwt.sha256(client_id);
    const apiKey = await this.env.DB.prepare(
      `SELECT * FROM api_keys WHERE id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`
    ).bind(client_id).first<any>();
    if (!apiKey) {
      return this.errorRedirect(redirect_uri, 'invalid_client', 'Unknown client_id', state);
    }

    // Check if user is already authenticated
    try {
      const context = await this.middleware.authenticate(request, false);
      if (context.user) {
        // User is authenticated — generate auth code
        const code = await this.generateAuthCode(client_id, context.user.id, apiKey.tenant_id, redirect_uri, scope || 'openid');
        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.set('code', code);
        if (state) redirectUrl.searchParams.set('state', state);
        return Response.redirect(redirectUrl.toString(), 302);
      }
    } catch {}

    // Not authenticated — redirect to login with OIDC params
    const loginUrl = new URL(`${this.env.APP_URL || url.origin}/login`);
    loginUrl.searchParams.set('oidc', '1');
    loginUrl.searchParams.set('client_id', client_id);
    loginUrl.searchParams.set('redirect_uri', redirect_uri);
    loginUrl.searchParams.set('scope', scope || 'openid');
    if (state) loginUrl.searchParams.set('state', state);
    return Response.redirect(loginUrl.toString(), 302);
  }

  // Token endpoint — exchange auth code for tokens
  async token(request: Request): Promise<Response> {
    let body: Record<string, string>;
    const contentType = request.headers.get('Content-Type') || '';

    if (contentType.includes('application/x-www-form-urlencoded')) {
      const text = await request.text();
      body = Object.fromEntries(new URLSearchParams(text));
    } else {
      body = await request.json() as any;
    }

    const { grant_type, code, redirect_uri, client_id, client_secret } = body;

    if (grant_type === 'authorization_code') {
      return this.handleAuthCodeExchange(code, redirect_uri, client_id, client_secret);
    } else if (grant_type === 'refresh_token') {
      return this.handleRefreshGrant(body.refresh_token, client_id);
    }

    return this.utils.errorResponse('Unsupported grant_type', 'UNSUPPORTED_GRANT', 400);
  }

  // UserInfo endpoint
  async userinfo(context: AuthContext): Promise<any> {
    if (!context.user) throw new Error('Unauthorized');
    const user = context.user;
    return {
      sub: String(user.id),
      email: user.email,
      email_verified: !!user.email_verified,
      updated_at: Math.floor(new Date(user.updated_at).getTime() / 1000),
    };
  }

  // --- Internal helpers ---

  private async generateAuthCode(
    clientId: string, userId: number, tenantId: number, redirectUri: string, scope: string
  ): Promise<string> {
    const code = crypto.randomUUID() + '-' + crypto.randomUUID();
    const codeHash = await this.jwt.sha256(code);
    const id = crypto.randomUUID();
    const expires = new Date(Date.now() + 600_000); // 10 minutes

    await this.env.DB.prepare(`
      INSERT INTO oidc_auth_codes (id, client_id, user_id, tenant_id, redirect_uri, scope, code_hash, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(id, clientId, userId, tenantId, redirectUri, scope, codeHash, expires.toISOString()).run();

    return code;
  }

  private async handleAuthCodeExchange(
    code: string, redirectUri: string, clientId: string, clientSecret?: string
  ): Promise<Response> {
    if (!code) return this.utils.errorResponse('code required', 'INVALID_REQUEST', 400);

    const codeHash = await this.jwt.sha256(code);
    const authCode = await this.env.DB.prepare(
      `SELECT * FROM oidc_auth_codes WHERE code_hash = ? AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP`
    ).bind(codeHash).first<any>();

    if (!authCode) {
      return this.utils.errorResponse('Invalid or expired authorization code', 'INVALID_GRANT', 400);
    }

    // Validate client
    if (authCode.client_id !== clientId) {
      return this.utils.errorResponse('client_id mismatch', 'INVALID_CLIENT', 401);
    }
    if (authCode.redirect_uri !== redirectUri) {
      return this.utils.errorResponse('redirect_uri mismatch', 'INVALID_REQUEST', 400);
    }

    // Mark code as used
    await this.env.DB.prepare(
      `UPDATE oidc_auth_codes SET used_at = CURRENT_TIMESTAMP WHERE id = ?`
    ).bind(authCode.id).run();

    // Get user
    const user = await this.db.getUserById(authCode.user_id);
    if (!user) return this.utils.errorResponse('User not found', 'INVALID_GRANT', 400);

    // Generate tokens
    const roles = authCode.tenant_id ? await this.db.getUserRoles(user.id, authCode.tenant_id) : [];
    const permissions = roles.flatMap((r: any) => r.permissions);

    const accessToken = await this.jwt.sign({
      sub: String(user.id),
      email: user.email,
      tid: authCode.tenant_id ? String(authCode.tenant_id) : undefined,
      roles: roles.map((r: any) => r.name),
      permissions,
    });

    // ID token (OIDC-specific)
    const idToken = await this.jwt.sign({
      sub: String(user.id),
      email: user.email,
    }, 3600);

    const refreshToken = await this.jwt.createRefreshToken(user.id, authCode.tenant_id);

    return new Response(JSON.stringify({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900,
      refresh_token: refreshToken,
      id_token: idToken,
      scope: authCode.scope,
    }), {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
      },
    });
  }

  private async handleRefreshGrant(refreshToken: string, clientId: string): Promise<Response> {
    if (!refreshToken) return this.utils.errorResponse('refresh_token required', 'INVALID_REQUEST', 400);

    try {
      const result = await this.jwt.rotateRefreshToken(refreshToken);
      return new Response(JSON.stringify({
        access_token: result.accessToken,
        token_type: 'Bearer',
        expires_in: 900,
        refresh_token: result.refreshToken,
      }), {
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      });
    } catch (e: any) {
      return this.utils.errorResponse(e.message, 'INVALID_GRANT', 400);
    }
  }

  private errorRedirect(redirectUri: string | undefined, error: string, description: string, state?: string): Response {
    if (!redirectUri) {
      return this.utils.errorResponse(description, error.toUpperCase(), 400);
    }
    const url = new URL(redirectUri);
    url.searchParams.set('error', error);
    url.searchParams.set('error_description', description);
    if (state) url.searchParams.set('state', state);
    return Response.redirect(url.toString(), 302);
  }
}
