// AuthNex JS API Client — Typed HTTP client for all auth operations

export interface AuthNexConfig {
  apiUrl: string;
  tenant?: string;
  apiKey?: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  user: UserData;
  tenant?: TenantData;
  force_password_reset?: boolean;
}

export interface UserData {
  id: number;
  email: string;
  email_verified?: boolean;
  status?: string;
  metadata?: Record<string, any>;
}

export interface TenantData {
  id: number;
  name: string;
  slug: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: { code: string; message: string };
}

export class AuthNexApiClient {
  private apiUrl: string;
  private tenant: string;
  private apiKey?: string;

  constructor(config: AuthNexConfig) {
    this.apiUrl = config.apiUrl.replace(/\/$/, '');
    this.tenant = config.tenant || '';
    this.apiKey = config.apiKey;
  }

  async login(email: string, password: string, rememberMe = true): Promise<LoginResponse> {
    const res = await this.post<LoginResponse>('/api/auth/login', {
      email, password, tenant_slug: this.tenant, remember_me: rememberMe,
    });
    return res;
  }

  async register(email: string, password: string, metadata?: Record<string, any>): Promise<{ user: UserData }> {
    return this.post<{ user: UserData }>('/api/auth/register', {
      email, password, tenant_slug: this.tenant, metadata,
    });
  }

  async refresh(refreshToken: string): Promise<LoginResponse> {
    return this.post<LoginResponse>('/api/auth/refresh', { refresh_token: refreshToken });
  }

  async logout(accessToken: string): Promise<void> {
    await this.post('/api/auth/logout', {}, accessToken);
  }

  async verifyEmail(token: string): Promise<{ message: string }> {
    return this.post<{ message: string }>('/api/auth/verify-email', { token });
  }

  async forgotPassword(email: string): Promise<{ message: string }> {
    return this.post<{ message: string }>('/api/auth/forgot-password', { email });
  }

  async resetPassword(token: string, password: string): Promise<{ message: string }> {
    return this.post<{ message: string }>('/api/auth/reset-password', { token, password });
  }

  async getProfile(accessToken: string): Promise<{ user: UserData }> {
    return this.get<{ user: UserData }>('/api/user/profile', accessToken);
  }

  private async post<T>(path: string, body: any, bearerToken?: string): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };
    if (this.tenant) headers['X-Tenant-Slug'] = this.tenant;
    if (this.apiKey) headers['X-API-Key'] = this.apiKey;
    if (bearerToken) headers['Authorization'] = `Bearer ${bearerToken}`;

    const response = await fetch(`${this.apiUrl}${path}`, {
      method: 'POST', headers, body: JSON.stringify(body),
    });

    return this.handleResponse<T>(response);
  }

  private async get<T>(path: string, bearerToken?: string): Promise<T> {
    const headers: Record<string, string> = { 'Accept': 'application/json' };
    if (this.tenant) headers['X-Tenant-Slug'] = this.tenant;
    if (this.apiKey) headers['X-API-Key'] = this.apiKey;
    if (bearerToken) headers['Authorization'] = `Bearer ${bearerToken}`;

    const response = await fetch(`${this.apiUrl}${path}`, { method: 'GET', headers });
    return this.handleResponse<T>(response);
  }

  private async handleResponse<T>(response: Response): Promise<T> {
    const data: ApiResponse<T> = await response.json();
    if (!data.success || !response.ok) {
      const msg = data.error?.message || `Request failed (${response.status})`;
      const err = new Error(msg) as any;
      err.code = data.error?.code || 'ERROR';
      err.status = response.status;
      throw err;
    }
    return data.data as T;
  }
}
