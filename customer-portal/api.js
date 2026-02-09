// Customer Portal API Client
class PortalApi {
  constructor() {
    this.baseUrl = '';
    this.accessToken = localStorage.getItem('cp_access_token');
    this.refreshToken = localStorage.getItem('cp_refresh_token');
    this.tenant = localStorage.getItem('cp_tenant_slug');
    this.refreshTimer = null;
    this.startAutoRefresh();
  }

  setTokens(accessToken, refreshToken, tenant) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.tenant = tenant;
    localStorage.setItem('cp_access_token', accessToken);
    if (refreshToken) localStorage.setItem('cp_refresh_token', refreshToken);
    if (tenant) localStorage.setItem('cp_tenant_slug', tenant);
  }

  clearTokens() {
    this.accessToken = null;
    this.refreshToken = null;
    localStorage.removeItem('cp_access_token');
    localStorage.removeItem('cp_refresh_token');
    localStorage.removeItem('cp_tenant_slug');
  }

  isAuthenticated() {
    return !!this.accessToken;
  }

  // Auth
  async login(email, password) {
    return this.post('/api/auth/login', { email, password, tenant_slug: this.tenant, remember_me: true });
  }

  async signup(email, password, companyName, tenantSlug, plan) {
    return this.post('/api/signup', { email, password, company_name: companyName, tenant_slug: tenantSlug, plan });
  }

  async refresh() {
    if (!this.refreshToken) throw new Error('No refresh token');
    const data = await this.post('/api/auth/refresh', { refresh_token: this.refreshToken });
    this.setTokens(data.access_token, data.refresh_token, this.tenant);
    return data;
  }

  async logout() {
    try { await this.post('/api/auth/logout', {}); } catch {}
    this.clearTokens();
  }

  // Portal endpoints
  async getDashboard() {
    return this.get('/api/portal/dashboard');
  }

  async getUsers(page = 1, limit = 20, search = '') {
    const params = new URLSearchParams({ page, limit, ...(search && { search }) });
    return this.get(`/api/portal/users?${params}`);
  }

  async getUsage() {
    return this.get('/api/portal/usage');
  }

  async getApiKeys() {
    return this.get('/api/admin/api-keys');
  }

  async createApiKey(data) {
    return this.post('/api/admin/api-keys', data);
  }

  async revokeApiKey(keyId) {
    return this.del(`/api/admin/api-keys/${keyId}`);
  }

  async getPlans() {
    return this.get('/api/plans');
  }

  async checkSlug(slug) {
    return this.get(`/api/check-slug?slug=${encodeURIComponent(slug)}`);
  }

  // HTTP helpers
  async get(path) {
    return this.request('GET', path);
  }

  async post(path, body) {
    return this.request('POST', path, body);
  }

  async del(path) {
    return this.request('DELETE', path);
  }

  async request(method, path, body) {
    const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
    if (this.accessToken) headers['Authorization'] = `Bearer ${this.accessToken}`;
    if (this.tenant) headers['X-Tenant-Slug'] = this.tenant;

    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);

    const response = await fetch(`${this.baseUrl}${path}`, opts);
    const data = await response.json();

    if (!response.ok) {
      if (response.status === 401 && this.refreshToken) {
        try {
          await this.refresh();
          headers['Authorization'] = `Bearer ${this.accessToken}`;
          const retry = await fetch(`${this.baseUrl}${path}`, { ...opts, headers });
          return (await retry.json()).data || (await retry.json());
        } catch {
          this.clearTokens();
          window.location.hash = '#login';
          throw new Error('Session expired');
        }
      }
      throw new Error(data.error?.message || `Request failed (${response.status})`);
    }
    return data.data || data;
  }

  startAutoRefresh() {
    this.refreshTimer = setInterval(async () => {
      if (!this.refreshToken) return;
      try {
        const token = this.accessToken;
        if (!token) return;
        const payload = JSON.parse(atob(token.split('.')[1]));
        if (payload.exp - Date.now() / 1000 < 120) {
          await this.refresh();
        }
      } catch {}
    }, 60000);
  }
}

const portalApi = new PortalApi();
