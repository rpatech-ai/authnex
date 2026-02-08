// Date: 2025-02-07
// Author: Alok
// File: src/jwt.ts
// Purpose: JWT sign/verify with RS256, refresh tokens, JWKS endpoint

import { JWTPayload, RefreshToken, Env } from './types';

// Reusable – copy to project reference
export class JWTService {
  private publicKey!: CryptoKey;
  private privateKey!: CryptoKey;

  constructor(private env: Env) {}

  async init(): Promise<void> {
    this.privateKey = await this.importKey(this.env.JWT_PRIVATE_KEY, 'private');
    this.publicKey = await this.importKey(this.env.JWT_PUBLIC_KEY, 'public');
  }

  private async importKey(pem: string, type: 'private' | 'public'): Promise<CryptoKey> {
    const header = type === 'private' ? 'PRIVATE KEY' : 'PUBLIC KEY';
    const cleaned = pem
      .replace(`-----BEGIN ${header}-----`, '')
      .replace(`-----END ${header}-----`, '')
      .replace(/\s/g, '');
    const binary = Uint8Array.from(atob(cleaned), c => c.charCodeAt(0));
    return crypto.subtle.importKey(
      type === 'private' ? 'pkcs8' : 'spki',
      binary,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      type === 'public', // exportable only for public (JWKS)
      type === 'private' ? ['sign'] : ['verify']
    );
  }

  // Sign JWT — no longer stores JTI in blacklist (that was backwards)
  async sign(payload: Omit<JWTPayload, 'iat' | 'exp' | 'jti'>, expiresIn = 900): Promise<string> {
    const header = { alg: 'RS256', typ: 'JWT', kid: 'primary' };
    const iat = Math.floor(Date.now() / 1000);
    const jti = crypto.randomUUID();
    const tokenPayload = { ...payload, iat, exp: iat + expiresIn, jti };

    const encoder = new TextEncoder();
    const headerB64 = this.base64url(JSON.stringify(header));
    const payloadB64 = this.base64url(JSON.stringify(tokenPayload));
    const message = `${headerB64}.${payloadB64}`;

    const signature = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5', this.privateKey, encoder.encode(message)
    );
    return `${message}.${this.base64url(signature)}`;
  }

  // Verify JWT — checks jti-based blacklist
  async verify(token: string): Promise<JWTPayload> {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid token format');
    const [headerB64, payloadB64, signatureB64] = parts;

    const payload: JWTPayload = JSON.parse(this.base64urlDecode(payloadB64));

    // Check blacklist by JTI (consistent key pattern)
    if (payload.jti) {
      const revoked = await this.env.BLACKLIST.get(`revoked:${payload.jti}`);
      if (revoked) throw new Error('Token revoked');
    }

    // Verify signature
    const encoder = new TextEncoder();
    const valid = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5', this.publicKey,
      this.base64urlToBuffer(signatureB64),
      encoder.encode(`${headerB64}.${payloadB64}`)
    );
    if (!valid) throw new Error('Invalid signature');

    // Check expiration
    if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');
    return payload;
  }

  // Revoke by extracting JTI from token — consistent with verify
  async revokeToken(token: string): Promise<void> {
    try {
      const [, payloadB64] = token.split('.');
      const payload = JSON.parse(this.base64urlDecode(payloadB64));
      if (payload.jti) {
        const ttl = Math.max(payload.exp - Math.floor(Date.now() / 1000), 60);
        await this.env.BLACKLIST.put(`revoked:${payload.jti}`, '1', { expirationTtl: ttl });
      }
    } catch { /* token may be malformed on logout, safe to ignore */ }
  }

  async createRefreshToken(userId: number, tenantId?: number): Promise<string> {
    const tokenId = crypto.randomUUID();
    const familyId = crypto.randomUUID();
    const token = `${tokenId}.${familyId}.${this.randomString(32)}`;
    const tokenHash = await this.sha256(token);
    const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await this.env.DB.prepare(`
      INSERT INTO refresh_tokens (id, user_id, tenant_id, token_hash, family_id, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(tokenId, userId, tenantId, tokenHash, familyId, expires.toISOString()).run();
    return token;
  }

  async rotateRefreshToken(token: string): Promise<{
    accessToken: string; refreshToken: string; userId: number; tenantId?: number;
  }> {
    const [tokenId, familyId] = token.split('.');
    const tokenHash = await this.sha256(token);

    const current = await this.env.DB.prepare(
      `SELECT * FROM refresh_tokens WHERE token_hash = ? AND revoked_at IS NULL`
    ).bind(tokenHash).first<RefreshToken>();
    if (!current) throw new Error('Invalid refresh token');
    if (new Date(current.expires_at) < new Date()) throw new Error('Refresh token expired');

    // Detect reuse — if other non-revoked tokens exist in family, it's compromised
    const siblings = await this.env.DB.prepare(
      `SELECT id FROM refresh_tokens WHERE family_id = ? AND id != ? AND revoked_at IS NULL`
    ).bind(current.family_id, current.id).all();

    if (siblings.results.length > 0) {
      await this.env.DB.prepare(
        `UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = 'Family compromised' WHERE family_id = ?`
      ).bind(current.family_id).run();
      throw new Error('Token family compromised');
    }

    // Revoke current, create new in same family
    await this.env.DB.prepare(
      `UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = 'Rotated' WHERE id = ?`
    ).bind(current.id).run();

    const newId = crypto.randomUUID();
    const newToken = `${newId}.${current.family_id}.${this.randomString(32)}`;
    const newHash = await this.sha256(newToken);
    const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await this.env.DB.prepare(
      `INSERT INTO refresh_tokens (id, user_id, tenant_id, token_hash, family_id, expires_at) VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(newId, current.user_id, current.tenant_id, newHash, current.family_id, expires.toISOString()).run();

    const user = await this.env.DB.prepare(`SELECT email FROM users WHERE id = ?`)
      .bind(current.user_id).first<{ email: string }>();

    const accessToken = await this.sign({
      sub: String(current.user_id),
      email: user!.email,
      tid: current.tenant_id ? String(current.tenant_id) : undefined,
    });

    return { accessToken, refreshToken: newToken, userId: current.user_id, tenantId: current.tenant_id || undefined };
  }

  async getJWKS(): Promise<any> {
    const jwk = await crypto.subtle.exportKey('jwk', this.publicKey);
    return { keys: [{ ...jwk, kid: 'primary', use: 'sig', alg: 'RS256' }] };
  }

  // --- Utilities ---
  private base64url(data: string | ArrayBuffer): string {
    const b64 = typeof data === 'string'
      ? btoa(data) : btoa(String.fromCharCode(...new Uint8Array(data)));
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }
  private base64urlDecode(str: string): string {
    const b64 = str.replace(/-/g, '+').replace(/_/g, '/').padEnd(str.length + (4 - str.length % 4) % 4, '=');
    return atob(b64);
  }
  private base64urlToBuffer(str: string): ArrayBuffer {
    const decoded = this.base64urlDecode(str);
    return Uint8Array.from(decoded, (_, i) => decoded.charCodeAt(i)).buffer;
  }
  async sha256(text: string): Promise<string> {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');
  }
  private randomString(len: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    return Array.from(crypto.getRandomValues(new Uint8Array(len)), v => chars[v % chars.length]).join('');
  }
}
