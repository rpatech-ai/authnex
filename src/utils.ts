// Date: 2025-02-07
// Author: Alok
// File: src/utils.ts
// Purpose: Password hashing, validation, email, rate limiting, webhook dispatch

import { Env, PasswordPolicy, WebhookEvent, TenantSettings } from './types';

// Reusable – copy to project reference
export class Utils {
  constructor(private env: Env) {}

  // PBKDF2 password hashing (Workers-compatible; Argon2id needs wasm/external)
  async hashPassword(password: string): Promise<string> {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const hash = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256
    );
    return `pbkdf2$${btoa(String.fromCharCode(...salt))}$${btoa(String.fromCharCode(...new Uint8Array(hash)))}`;
  }

  async verifyPassword(password: string, stored: string): Promise<boolean> {
    const [alg, saltB64, hashB64] = stored.split('$');
    if (alg !== 'pbkdf2') return false;
    const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
    const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const hash = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256
    );
    return this.timingSafeEqual(hashB64, btoa(String.fromCharCode(...new Uint8Array(hash))));
  }

  private timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let r = 0;
    for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return r === 0;
  }

  validateEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 255;
  }

  validatePassword(password: string, policy?: PasswordPolicy): string | null {
    const p = { minLength: 8, requireUppercase: true, requireLowercase: true, requireNumbers: true, requireSpecialChars: false, ...policy };
    if (password.length < (p.minLength || 8)) return `Password must be at least ${p.minLength} characters`;
    if (p.requireUppercase && !/[A-Z]/.test(password)) return 'Must contain uppercase letter';
    if (p.requireLowercase && !/[a-z]/.test(password)) return 'Must contain lowercase letter';
    if (p.requireNumbers && !/\d/.test(password)) return 'Must contain number';
    if (p.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) return 'Must contain special character';
    return null;
  }

  async sendEmail(to: string, subject: string, html: string): Promise<void> {
    const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${this.env.SMTP_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: to }] }],
        from: { email: this.env.SMTP_FROM || 'noreply@example.com' },
        subject, content: [{ type: 'text/html', value: html }]
      })
    });
    if (!response.ok) throw new Error(`Email failed: ${response.statusText}`);
  }

  getEmailTemplate(type: 'verify' | 'reset' | 'welcome', data: any): string {
    const wrap = (body: string) => `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">${body}</div>`;
    const btn = (href: string, label: string, color = '#007bff') =>
      `<a href="${href}" style="display:inline-block;padding:10px 20px;background:${color};color:white;text-decoration:none;border-radius:5px">${label}</a>`;
    const templates: Record<string, string> = {
      verify: wrap(`<h2>Verify Your Email</h2><p>Click below to verify:</p>${btn(data.link, 'Verify Email')}<p style="color:#666;font-size:12px">Expires in ${data.expiry} hours.</p>`),
      reset: wrap(`<h2>Reset Your Password</h2><p>Click below to reset:</p>${btn(data.link, 'Reset Password')}<p style="color:#666;font-size:12px">Expires in ${data.expiry} hour. Ignore if not requested.</p>`),
      welcome: wrap(`<h2>Welcome to ${data.tenantName || 'Our Platform'}!</h2><p>Account created. Email: ${data.email}</p>${btn(data.loginUrl, 'Login Now', '#28a745')}`),
    };
    return templates[type];
  }

  generateToken(length = 32): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    return Array.from(crypto.getRandomValues(new Uint8Array(length)), v => chars[v % chars.length]).join('');
  }

  getClientIP(request: Request): string {
    return request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For')?.split(',')[0] || 'unknown';
  }

  getUserAgent(request: Request): string {
    return request.headers.get('User-Agent') || 'unknown';
  }

  sanitizeInput(input: string): string {
    return input.trim().replace(/[<>]/g, '').slice(0, 1000);
  }

  // Webhook dispatcher — fire-and-forget for configured tenant webhooks
  async dispatchWebhook(tenantSettings: TenantSettings | undefined, event: WebhookEvent): Promise<void> {
    if (!tenantSettings?.webhooks?.length) return;
    for (const hook of tenantSettings.webhooks) {
      if (!hook.events.includes(event.event) && !hook.events.includes('*')) continue;
      try {
        const body = JSON.stringify(event);
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (hook.secret) {
          const sig = await this.hmacSha256(hook.secret, body);
          headers['X-Webhook-Signature'] = sig;
        }
        // Fire and forget — don't await
        fetch(hook.url, { method: 'POST', headers, body }).catch(() => {});
      } catch { /* webhook failure should never break auth flow */ }
    }
  }

  private async hmacSha256(secret: string, data: string): Promise<string> {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
    return Array.from(new Uint8Array(sig), b => b.toString(16).padStart(2, '0')).join('');
  }

  // CSRF token generation
  generateCSRFToken(): string { return this.generateToken(32); }

  verifyCSRFToken(token: string, sessionToken: string): boolean {
    return token === sessionToken && token.length === 32;
  }

  errorResponse(message: string, code = 'ERROR', status = 400): Response {
    return new Response(JSON.stringify({
      success: false, error: { code, message, timestamp: new Date().toISOString() }
    }), { status, headers: { 'Content-Type': 'application/json' } });
  }

  successResponse(data: any, status = 200): Response {
    return new Response(JSON.stringify({ success: true, data }), {
      status, headers: { 'Content-Type': 'application/json' }
    });
  }

  async sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
