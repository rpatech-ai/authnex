// Date: 2026-02-09
// File: src/webauthn.ts
// Purpose: WebAuthn/Passkey registration and authentication ceremonies

import { Env, AuthContext, User } from './types';
import { Database } from './db';
import { JWTService } from './jwt';
import { Utils } from './utils';

// WebAuthn types
interface PublicKeyCredentialCreationOptions {
  rp: { name: string; id: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: { type: string; alg: number }[];
  timeout: number;
  authenticatorSelection: {
    authenticatorAttachment?: string;
    residentKey: string;
    requireResidentKey: boolean;
    userVerification: string;
  };
  attestation: string;
  excludeCredentials?: { id: string; type: string; transports?: string[] }[];
}

interface PublicKeyCredentialRequestOptions {
  challenge: string;
  timeout: number;
  rpId: string;
  allowCredentials?: { id: string; type: string; transports?: string[] }[];
  userVerification: string;
}

export class WebAuthnService {
  private db: Database;
  private jwt: JWTService;
  private utils: Utils;
  private rpName = 'AuthNex';
  private rpId: string;

  constructor(private env: Env) {
    this.db = new Database(env);
    this.jwt = new JWTService(env);
    this.utils = new Utils(env);
    // RP ID is the domain (extracted from APP_URL or defaults)
    const appUrl = env.APP_URL || 'https://authnex.com';
    this.rpId = new URL(appUrl).hostname;
  }

  async init(): Promise<void> { await this.jwt.init(); }

  // --- Registration ---

  // Generate registration options for a user
  async generateRegistrationOptions(context: AuthContext, deviceName?: string): Promise<{
    options: PublicKeyCredentialCreationOptions;
    challengeId: string;
  }> {
    if (!context.user) throw new Error('Not authenticated');

    // Get existing credentials to exclude
    const existing = await this.env.DB.prepare(
      `SELECT credential_id, transports FROM webauthn_credentials WHERE user_id = ?`
    ).bind(context.user.id).all<any>();

    const challenge = this.generateChallenge();
    const challengeId = crypto.randomUUID();
    const expires = new Date(Date.now() + 300_000); // 5 minutes

    await this.env.DB.prepare(`
      INSERT INTO webauthn_challenges (id, user_id, challenge, type, expires_at)
      VALUES (?, ?, ?, 'registration', ?)
    `).bind(challengeId, context.user.id, challenge, expires.toISOString()).run();

    const options: PublicKeyCredentialCreationOptions = {
      rp: { name: this.rpName, id: this.rpId },
      user: {
        id: this.bufferToBase64url(new TextEncoder().encode(String(context.user.id))),
        name: context.user.email,
        displayName: (context.user.metadata as any)?.name || context.user.email,
      },
      challenge,
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },    // ES256
        { type: 'public-key', alg: -257 },  // RS256
      ],
      timeout: 300000,
      authenticatorSelection: {
        residentKey: 'preferred',
        requireResidentKey: false,
        userVerification: 'preferred',
      },
      attestation: 'none',
      excludeCredentials: existing.results.map(c => ({
        id: c.credential_id,
        type: 'public-key',
        transports: JSON.parse(c.transports || '[]'),
      })),
    };

    return { options, challengeId };
  }

  // Verify registration response and store credential
  async verifyRegistration(context: AuthContext, body: {
    challengeId: string;
    credentialId: string;
    publicKey: string;
    clientDataJSON: string;
    attestationObject: string;
    transports?: string[];
    deviceName?: string;
  }): Promise<{ credentialId: string; deviceName: string }> {
    if (!context.user) throw new Error('Not authenticated');

    // Validate challenge
    const challenge = await this.env.DB.prepare(
      `SELECT * FROM webauthn_challenges WHERE id = ? AND user_id = ? AND type = 'registration' AND expires_at > CURRENT_TIMESTAMP`
    ).bind(body.challengeId, context.user.id).first<any>();

    if (!challenge) throw new Error('Invalid or expired challenge');

    // Verify clientDataJSON
    const clientData = JSON.parse(atob(body.clientDataJSON));
    if (clientData.type !== 'webauthn.create') throw new Error('Invalid ceremony type');

    // Verify challenge matches
    if (clientData.challenge !== challenge.challenge) throw new Error('Challenge mismatch');

    // Verify origin
    const expectedOrigin = this.env.APP_URL || `https://${this.rpId}`;
    if (clientData.origin !== expectedOrigin) {
      // Allow localhost for development
      if (!clientData.origin.startsWith('http://localhost')) {
        throw new Error('Origin mismatch');
      }
    }

    // Delete used challenge
    await this.env.DB.prepare(`DELETE FROM webauthn_challenges WHERE id = ?`).bind(body.challengeId).run();

    // Store credential
    const id = crypto.randomUUID();
    const deviceName = body.deviceName || 'Passkey';

    await this.env.DB.prepare(`
      INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, device_name, transports)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      id, context.user.id, body.credentialId, body.publicKey,
      deviceName, JSON.stringify(body.transports || [])
    ).run();

    await this.db.logAudit({
      user_id: context.user.id, action: 'webauthn_registered',
      resource_type: 'webauthn_credential', resource_id: id,
      changes: { device_name: deviceName }, success: true,
    });

    return { credentialId: body.credentialId, deviceName };
  }

  // --- Authentication ---

  // Generate authentication options
  async generateAuthenticationOptions(email?: string, tenantSlug?: string): Promise<{
    options: PublicKeyCredentialRequestOptions;
    challengeId: string;
  }> {
    let allowCredentials: any[] | undefined;
    let userId: number | undefined;

    if (email) {
      const user = await this.db.getUserByEmail(email);
      if (user) {
        userId = user.id;
        const creds = await this.env.DB.prepare(
          `SELECT credential_id, transports FROM webauthn_credentials WHERE user_id = ?`
        ).bind(user.id).all<any>();

        if (creds.results.length === 0) throw new Error('No passkeys registered for this account');

        allowCredentials = creds.results.map(c => ({
          id: c.credential_id,
          type: 'public-key',
          transports: JSON.parse(c.transports || '[]'),
        }));
      }
    }

    const challenge = this.generateChallenge();
    const challengeId = crypto.randomUUID();
    const expires = new Date(Date.now() + 300_000);

    await this.env.DB.prepare(`
      INSERT INTO webauthn_challenges (id, user_id, challenge, type, expires_at)
      VALUES (?, ?, ?, 'authentication', ?)
    `).bind(challengeId, userId || null, challenge, expires.toISOString()).run();

    const options: PublicKeyCredentialRequestOptions = {
      challenge,
      timeout: 300000,
      rpId: this.rpId,
      allowCredentials,
      userVerification: 'preferred',
    };

    return { options, challengeId };
  }

  // Verify authentication response
  async verifyAuthentication(body: {
    challengeId: string;
    credentialId: string;
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
    tenantSlug?: string;
  }, ipAddress: string, userAgent: string): Promise<{
    access_token: string; refresh_token: string; expires_in: number; user: Partial<User>;
  }> {
    // Validate challenge
    const challenge = await this.env.DB.prepare(
      `SELECT * FROM webauthn_challenges WHERE id = ? AND type = 'authentication' AND expires_at > CURRENT_TIMESTAMP`
    ).bind(body.challengeId).first<any>();

    if (!challenge) throw new Error('Invalid or expired challenge');

    // Look up credential
    const credential = await this.env.DB.prepare(
      `SELECT * FROM webauthn_credentials WHERE credential_id = ?`
    ).bind(body.credentialId).first<any>();

    if (!credential) throw new Error('Unknown credential');

    // Verify clientDataJSON
    const clientData = JSON.parse(atob(body.clientDataJSON));
    if (clientData.type !== 'webauthn.get') throw new Error('Invalid ceremony type');
    if (clientData.challenge !== challenge.challenge) throw new Error('Challenge mismatch');

    // Delete used challenge
    await this.env.DB.prepare(`DELETE FROM webauthn_challenges WHERE id = ?`).bind(body.challengeId).run();

    // Update counter
    await this.env.DB.prepare(
      `UPDATE webauthn_credentials SET counter = counter + 1, last_used_at = CURRENT_TIMESTAMP WHERE id = ?`
    ).bind(credential.id).run();

    // Get user
    const user = await this.db.getUserById(credential.user_id);
    if (!user) throw new Error('User not found');
    if (user.status === 'locked') throw new Error('Account locked');
    if (user.status === 'deleted') throw new Error('Account not found');

    // Resolve tenant
    let tenantId: number | undefined;
    let roles: any[] = [];
    let permissions: string[] = [];

    if (body.tenantSlug) {
      const tenant = await this.db.getTenantBySlug(body.tenantSlug);
      if (tenant) {
        tenantId = tenant.id;
        roles = await this.db.getUserRoles(user.id, tenant.id);
        permissions = roles.flatMap(r => r.permissions);
      }
    }

    // Generate tokens
    const accessToken = await this.jwt.sign({
      sub: String(user.id), email: user.email,
      tid: tenantId ? String(tenantId) : undefined,
      roles: roles.map(r => r.name), permissions,
    });
    const refreshToken = await this.jwt.createRefreshToken(user.id, tenantId);

    await this.db.logAudit({
      tenant_id: tenantId, user_id: user.id,
      action: 'webauthn_login', ip_address: ipAddress,
      user_agent: userAgent, success: true,
    });

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 900,
      user: { id: user.id, email: user.email, status: user.status },
    };
  }

  // List user's registered passkeys
  async listCredentials(userId: number): Promise<any[]> {
    const result = await this.env.DB.prepare(
      `SELECT id, credential_id, device_name, transports, created_at, last_used_at FROM webauthn_credentials WHERE user_id = ?`
    ).bind(userId).all<any>();
    return result.results;
  }

  // Remove a passkey
  async removeCredential(context: AuthContext, credentialId: string): Promise<void> {
    if (!context.user) throw new Error('Not authenticated');

    // Ensure user keeps at least one auth method
    const count = await this.env.DB.prepare(
      `SELECT COUNT(*) as c FROM webauthn_credentials WHERE user_id = ?`
    ).bind(context.user.id).first<{ c: number }>();

    if ((count?.c || 0) <= 1) {
      throw new Error('Cannot remove the last passkey. Add another authentication method first.');
    }

    await this.env.DB.prepare(
      `DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?`
    ).bind(credentialId, context.user.id).run();

    await this.db.logAudit({
      user_id: context.user.id, action: 'webauthn_removed',
      resource_type: 'webauthn_credential', resource_id: credentialId, success: true,
    });
  }

  // --- Helpers ---

  private generateChallenge(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    return this.bufferToBase64url(bytes);
  }

  private bufferToBase64url(buffer: Uint8Array): string {
    const b64 = btoa(String.fromCharCode(...buffer));
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }
}
