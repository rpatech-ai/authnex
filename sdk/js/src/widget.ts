// AuthNex Login Widget — Drop-in login/register UI component
// Usage: AuthNex.init({ container: '#authnex-login', apiUrl: '...', tenant: '...' })

import { AuthNexApiClient, LoginResponse, UserData } from './api-client';

export interface WidgetConfig {
  container: string;
  apiUrl: string;
  tenant?: string;
  apiKey?: string;
  theme?: 'light' | 'dark';
  logo?: string;
  title?: string;
  showRegister?: boolean;
  showForgotPassword?: boolean;
  showRememberMe?: boolean;
  redirectUrl?: string;
  primaryColor?: string;
  onLogin?: (user: UserData, tokens: { access_token: string; refresh_token?: string }) => void;
  onRegister?: (user: UserData) => void;
  onLogout?: () => void;
  onError?: (error: Error) => void;
}

type WidgetView = 'login' | 'register' | 'forgot-password' | 'reset-password' | 'verify-email';

const TOKEN_KEY = 'authnex_tokens';
const USER_KEY = 'authnex_user';

class AuthNexWidget {
  private config: WidgetConfig;
  private client: AuthNexApiClient;
  private container: HTMLElement;
  private currentView: WidgetView = 'login';
  private refreshTimer?: ReturnType<typeof setInterval>;

  constructor(config: WidgetConfig) {
    this.config = {
      theme: 'light',
      showRegister: true,
      showForgotPassword: true,
      showRememberMe: true,
      title: 'Welcome',
      ...config,
    };

    const el = document.querySelector(this.config.container);
    if (!el) throw new Error(`Container not found: ${this.config.container}`);
    this.container = el as HTMLElement;

    this.client = new AuthNexApiClient({
      apiUrl: this.config.apiUrl,
      tenant: this.config.tenant || el.getAttribute('data-tenant') || '',
      apiKey: this.config.apiKey,
    });

    this.injectStyles();
    this.render();
    this.startAutoRefresh();
  }

  // --- Public API ---

  getUser(): UserData | null {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  }

  getAccessToken(): string | null {
    const tokens = this.getTokens();
    return tokens?.access_token || null;
  }

  isAuthenticated(): boolean {
    return !!this.getAccessToken();
  }

  async logout(): Promise<void> {
    const tokens = this.getTokens();
    if (tokens?.access_token) {
      try { await this.client.logout(tokens.access_token); } catch {}
    }
    this.clearTokens();
    this.config.onLogout?.();
    this.currentView = 'login';
    this.render();
  }

  destroy(): void {
    if (this.refreshTimer) clearInterval(this.refreshTimer);
    this.container.innerHTML = '';
  }

  // --- Render ---

  private render(): void {
    const theme = this.config.theme === 'dark' ? ' dark' : '';
    switch (this.currentView) {
      case 'login': this.renderLogin(theme); break;
      case 'register': this.renderRegister(theme); break;
      case 'forgot-password': this.renderForgotPassword(theme); break;
      default: this.renderLogin(theme);
    }
  }

  private renderLogin(theme: string): void {
    const c = this.config;
    this.container.innerHTML = `
      <div class="authnex-widget${theme}">
        ${this.renderHeader('Sign In', 'Enter your credentials to continue')}
        <div class="authnex-error" id="authnex-error"></div>
        <form id="authnex-login-form">
          <div class="authnex-form-group">
            <label for="authnex-email">Email</label>
            <input type="email" id="authnex-email" placeholder="you@example.com" required autocomplete="email" />
          </div>
          <div class="authnex-form-group">
            <label for="authnex-password">Password</label>
            <input type="password" id="authnex-password" placeholder="Enter your password" required autocomplete="current-password" />
          </div>
          ${c.showRememberMe ? `
          <div class="authnex-checkbox">
            <input type="checkbox" id="authnex-remember" checked />
            <label for="authnex-remember">Remember me</label>
          </div>` : ''}
          <button type="submit" class="authnex-btn" id="authnex-submit">Sign In</button>
        </form>
        <div class="authnex-footer">
          ${c.showForgotPassword ? `<a id="authnex-forgot-link">Forgot password?</a>` : ''}
          ${c.showRegister ? `<p>Don't have an account? <a id="authnex-register-link">Sign up</a></p>` : ''}
        </div>
        <div class="authnex-powered">Secured by AuthNex</div>
      </div>`;
    this.bindLoginEvents();
  }

  private renderRegister(theme: string): void {
    this.container.innerHTML = `
      <div class="authnex-widget${theme}">
        ${this.renderHeader('Create Account', 'Sign up to get started')}
        <div class="authnex-error" id="authnex-error"></div>
        <div class="authnex-success" id="authnex-success"></div>
        <form id="authnex-register-form">
          <div class="authnex-form-group">
            <label for="authnex-reg-email">Email</label>
            <input type="email" id="authnex-reg-email" placeholder="you@example.com" required autocomplete="email" />
          </div>
          <div class="authnex-form-group">
            <label for="authnex-reg-password">Password</label>
            <input type="password" id="authnex-reg-password" placeholder="Min 8 chars, mixed case + number" required autocomplete="new-password" />
          </div>
          <div class="authnex-form-group">
            <label for="authnex-reg-confirm">Confirm Password</label>
            <input type="password" id="authnex-reg-confirm" placeholder="Re-enter your password" required autocomplete="new-password" />
          </div>
          <button type="submit" class="authnex-btn" id="authnex-submit">Create Account</button>
        </form>
        <div class="authnex-footer">
          <p>Already have an account? <a id="authnex-login-link">Sign in</a></p>
        </div>
        <div class="authnex-powered">Secured by AuthNex</div>
      </div>`;
    this.bindRegisterEvents();
  }

  private renderForgotPassword(theme: string): void {
    this.container.innerHTML = `
      <div class="authnex-widget${theme}">
        ${this.renderHeader('Reset Password', 'Enter your email to receive a reset link')}
        <div class="authnex-error" id="authnex-error"></div>
        <div class="authnex-success" id="authnex-success"></div>
        <form id="authnex-forgot-form">
          <div class="authnex-form-group">
            <label for="authnex-forgot-email">Email</label>
            <input type="email" id="authnex-forgot-email" placeholder="you@example.com" required autocomplete="email" />
          </div>
          <button type="submit" class="authnex-btn" id="authnex-submit">Send Reset Link</button>
        </form>
        <div class="authnex-footer">
          <a id="authnex-back-login">Back to sign in</a>
        </div>
        <div class="authnex-powered">Secured by AuthNex</div>
      </div>`;
    this.bindForgotEvents();
  }

  private renderHeader(title: string, subtitle: string): string {
    return `
      <div class="authnex-header">
        ${this.config.logo ? `<img class="authnex-logo" src="${this.config.logo}" alt="Logo" />` : ''}
        <h2>${this.config.title || title}</h2>
        <p>${subtitle}</p>
      </div>`;
  }

  // --- Event Binding ---

  private bindLoginEvents(): void {
    const form = document.getElementById('authnex-login-form');
    form?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = (document.getElementById('authnex-email') as HTMLInputElement).value;
      const password = (document.getElementById('authnex-password') as HTMLInputElement).value;
      const remember = (document.getElementById('authnex-remember') as HTMLInputElement)?.checked ?? true;
      await this.handleLogin(email, password, remember);
    });

    document.getElementById('authnex-register-link')?.addEventListener('click', () => {
      this.currentView = 'register';
      this.render();
    });

    document.getElementById('authnex-forgot-link')?.addEventListener('click', () => {
      this.currentView = 'forgot-password';
      this.render();
    });
  }

  private bindRegisterEvents(): void {
    const form = document.getElementById('authnex-register-form');
    form?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = (document.getElementById('authnex-reg-email') as HTMLInputElement).value;
      const password = (document.getElementById('authnex-reg-password') as HTMLInputElement).value;
      const confirm = (document.getElementById('authnex-reg-confirm') as HTMLInputElement).value;

      if (password !== confirm) {
        this.showError('Passwords do not match');
        return;
      }
      await this.handleRegister(email, password);
    });

    document.getElementById('authnex-login-link')?.addEventListener('click', () => {
      this.currentView = 'login';
      this.render();
    });
  }

  private bindForgotEvents(): void {
    const form = document.getElementById('authnex-forgot-form');
    form?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = (document.getElementById('authnex-forgot-email') as HTMLInputElement).value;
      await this.handleForgotPassword(email);
    });

    document.getElementById('authnex-back-login')?.addEventListener('click', () => {
      this.currentView = 'login';
      this.render();
    });
  }

  // --- Action Handlers ---

  private async handleLogin(email: string, password: string, remember: boolean): Promise<void> {
    this.setLoading(true);
    this.hideMessages();
    try {
      const result = await this.client.login(email, password, remember);
      this.saveTokens(result);
      const user: UserData = result.user;
      localStorage.setItem(USER_KEY, JSON.stringify(user));
      this.config.onLogin?.(user, {
        access_token: result.access_token,
        refresh_token: result.refresh_token,
      });
      if (this.config.redirectUrl) {
        window.location.href = this.config.redirectUrl;
      }
    } catch (error: any) {
      this.showError(error.message || 'Login failed');
      this.config.onError?.(error);
    } finally {
      this.setLoading(false);
    }
  }

  private async handleRegister(email: string, password: string): Promise<void> {
    this.setLoading(true);
    this.hideMessages();
    try {
      const result = await this.client.register(email, password);
      this.showSuccess('Account created! Check your email to verify.');
      this.config.onRegister?.(result.user);
      setTimeout(() => {
        this.currentView = 'login';
        this.render();
      }, 3000);
    } catch (error: any) {
      this.showError(error.message || 'Registration failed');
      this.config.onError?.(error);
    } finally {
      this.setLoading(false);
    }
  }

  private async handleForgotPassword(email: string): Promise<void> {
    this.setLoading(true);
    this.hideMessages();
    try {
      await this.client.forgotPassword(email);
      this.showSuccess('If the email exists, a reset link was sent.');
    } catch (error: any) {
      this.showError(error.message || 'Request failed');
      this.config.onError?.(error);
    } finally {
      this.setLoading(false);
    }
  }

  // --- Token Management ---

  private saveTokens(data: LoginResponse): void {
    localStorage.setItem(TOKEN_KEY, JSON.stringify({
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at: Date.now() + (data.expires_in * 1000),
    }));
  }

  private getTokens(): { access_token: string; refresh_token?: string; expires_at: number } | null {
    const raw = localStorage.getItem(TOKEN_KEY);
    return raw ? JSON.parse(raw) : null;
  }

  private clearTokens(): void {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  }

  private startAutoRefresh(): void {
    this.refreshTimer = setInterval(async () => {
      const tokens = this.getTokens();
      if (!tokens?.refresh_token) return;
      // Refresh 60s before expiry
      if (tokens.expires_at - Date.now() < 60_000) {
        try {
          const result = await this.client.refresh(tokens.refresh_token);
          this.saveTokens(result);
        } catch {
          this.clearTokens();
          this.currentView = 'login';
          this.render();
        }
      }
    }, 30_000);
  }

  // --- UI Helpers ---

  private showError(msg: string): void {
    const el = document.getElementById('authnex-error');
    if (el) { el.textContent = msg; el.classList.add('visible'); }
  }

  private showSuccess(msg: string): void {
    const el = document.getElementById('authnex-success');
    if (el) { el.textContent = msg; el.classList.add('visible'); }
  }

  private hideMessages(): void {
    document.getElementById('authnex-error')?.classList.remove('visible');
    document.getElementById('authnex-success')?.classList.remove('visible');
  }

  private setLoading(loading: boolean): void {
    const btn = document.getElementById('authnex-submit') as HTMLButtonElement;
    if (!btn) return;
    if (loading) {
      btn.disabled = true;
      btn.dataset.originalText = btn.textContent || '';
      btn.innerHTML = '<span class="spinner"></span> Please wait...';
    } else {
      btn.disabled = false;
      btn.textContent = btn.dataset.originalText || 'Submit';
    }
  }

  private injectStyles(): void {
    if (document.getElementById('authnex-widget-styles')) return;
    const link = document.createElement('style');
    link.id = 'authnex-widget-styles';
    // Inline the CSS so it works from CDN without extra file loads
    link.textContent = `
      .authnex-widget{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;max-width:400px;margin:0 auto;padding:32px;border-radius:12px;background:var(--authnex-bg,#fff);color:var(--authnex-text,#1a1a2e);box-shadow:0 4px 24px rgba(0,0,0,.1);box-sizing:border-box}
      .authnex-widget *{box-sizing:border-box}
      .authnex-widget.dark{--authnex-bg:#1a1a2e;--authnex-text:#e0e0e0;--authnex-input-bg:#16213e;--authnex-input-border:#0f3460;--authnex-primary:#e94560;--authnex-primary-hover:#c23152;--authnex-link:#53a8ff;--authnex-error-bg:#3a1525;--authnex-error-text:#ff6b6b;--authnex-success-bg:#153a2a;--authnex-success-text:#4ade80}
      .authnex-header{text-align:center;margin-bottom:24px}.authnex-header h2{margin:0 0 4px;font-size:24px;font-weight:700;color:var(--authnex-text,#1a1a2e)}.authnex-header p{margin:0;font-size:14px;color:#6b7280}
      .authnex-logo{width:48px;height:48px;margin:0 auto 12px;display:block}
      .authnex-form-group{margin-bottom:16px}.authnex-form-group label{display:block;margin-bottom:6px;font-size:14px;font-weight:500;color:var(--authnex-text,#374151)}.authnex-form-group input{width:100%;padding:10px 14px;font-size:14px;border:1px solid var(--authnex-input-border,#d1d5db);border-radius:8px;background:var(--authnex-input-bg,#fff);color:var(--authnex-text,#1a1a2e);outline:none;transition:border-color .2s}.authnex-form-group input:focus{border-color:var(--authnex-primary,#3b82f6);box-shadow:0 0 0 3px rgba(59,130,246,.15)}
      .authnex-btn{width:100%;padding:12px;font-size:15px;font-weight:600;color:#fff;background:var(--authnex-primary,#3b82f6);border:none;border-radius:8px;cursor:pointer;transition:background .2s,opacity .2s}.authnex-btn:hover{background:var(--authnex-primary-hover,#2563eb)}.authnex-btn:disabled{opacity:.6;cursor:not-allowed}
      .authnex-btn .spinner{display:inline-block;width:16px;height:16px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:authnex-spin .6s linear infinite;vertical-align:middle;margin-right:8px}@keyframes authnex-spin{to{transform:rotate(360deg)}}
      .authnex-error{padding:10px 14px;margin-bottom:16px;font-size:13px;border-radius:8px;background:var(--authnex-error-bg,#fef2f2);color:var(--authnex-error-text,#dc2626);display:none}.authnex-error.visible{display:block}
      .authnex-success{padding:10px 14px;margin-bottom:16px;font-size:13px;border-radius:8px;background:var(--authnex-success-bg,#f0fdf4);color:var(--authnex-success-text,#16a34a);display:none}.authnex-success.visible{display:block}
      .authnex-footer{text-align:center;margin-top:16px;font-size:13px;color:#6b7280}.authnex-footer a{color:var(--authnex-link,#3b82f6);text-decoration:none;cursor:pointer}.authnex-footer a:hover{text-decoration:underline}
      .authnex-checkbox{display:flex;align-items:center;gap:8px;margin-bottom:16px;font-size:13px;color:var(--authnex-text,#374151)}.authnex-checkbox input[type=checkbox]{width:16px;height:16px}
      .authnex-powered{text-align:center;margin-top:20px;font-size:11px;color:#9ca3af}
      @media(max-width:480px){.authnex-widget{margin:0;border-radius:0;box-shadow:none;padding:24px 16px}}
    `;
    document.head.appendChild(link);
  }
}

// --- Global singleton API ---
let _instance: AuthNexWidget | null = null;

const AuthNex = {
  init(config: WidgetConfig): AuthNexWidget {
    if (_instance) _instance.destroy();
    _instance = new AuthNexWidget(config);
    return _instance;
  },

  onLogin(cb: (user: UserData, tokens: { access_token: string; refresh_token?: string }) => void): void {
    if (_instance) (_instance as any).config.onLogin = cb;
  },

  onRegister(cb: (user: UserData) => void): void {
    if (_instance) (_instance as any).config.onRegister = cb;
  },

  onLogout(cb: () => void): void {
    if (_instance) (_instance as any).config.onLogout = cb;
  },

  onError(cb: (error: Error) => void): void {
    if (_instance) (_instance as any).config.onError = cb;
  },

  getUser(): UserData | null {
    return _instance?.getUser() || null;
  },

  getAccessToken(): string | null {
    return _instance?.getAccessToken() || null;
  },

  isAuthenticated(): boolean {
    return _instance?.isAuthenticated() || false;
  },

  logout(): Promise<void> {
    return _instance?.logout() || Promise.resolve();
  },

  destroy(): void {
    _instance?.destroy();
    _instance = null;
  },
};

// UMD export for CDN usage
if (typeof window !== 'undefined') {
  (window as any).AuthNex = AuthNex;
}

export { AuthNex, AuthNexWidget };
export type { WidgetConfig, UserData };
