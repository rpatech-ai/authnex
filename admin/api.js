// Date: 2025-02-07
// Author: Alok
// File: admin/api.js
// Purpose: API client for admin operations

class AuthAPI {
  constructor() {
    this.baseUrl = window.location.hostname === 'localhost'
      ? 'http://localhost:8787/api' : '/api';
    this.token = localStorage.getItem('authToken');
    this.tenantSlug = localStorage.getItem('tenantSlug');
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = { 'Content-Type': 'application/json', ...options.headers };
    if (this.token) headers['Authorization'] = `Bearer ${this.token}`;
    if (this.tenantSlug) headers['X-Tenant-Slug'] = this.tenantSlug;

    try {
      const fetchOpts = { ...options, headers };
      // Only attach body for non-GET methods
      if (options.body && options.method && options.method !== 'GET') {
        fetchOpts.body = JSON.stringify(options.body);
      }
      delete fetchOpts.body; // remove from spread
      const response = await fetch(url, {
        method: options.method || 'GET',
        headers,
        ...(options.body && options.method !== 'GET' ? { body: JSON.stringify(options.body) } : {}),
      });
      const data = await response.json();
      if (!response.ok) {
        if (response.status === 401) this.handleAuthError();
        throw new Error(data.error?.message || 'Request failed');
      }
      return data.data || data;
    } catch (error) {
      console.error('API error:', error);
      throw error;
    }
  }

  handleAuthError() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('refreshToken');
    window.location.href = 'login.html';
  }

  setTenant(slug) {
    this.tenantSlug = slug;
    slug ? localStorage.setItem('tenantSlug', slug) : localStorage.removeItem('tenantSlug');
  }

  // Auth
  async login(email, password, tenantSlug = null) {
    const r = await this.request('/auth/login', {
      method: 'POST', body: { email, password, tenant_slug: tenantSlug, remember_me: true }
    });
    if (r.access_token) {
      this.token = r.access_token;
      localStorage.setItem('authToken', r.access_token);
      if (r.refresh_token) localStorage.setItem('refreshToken', r.refresh_token);
    }
    return r;
  }

  async setup(email, password, tenantName, tenantSlug) {
    return this.request('/auth/setup', {
      method: 'POST', body: { email, password, tenant_name: tenantName, tenant_slug: tenantSlug }
    });
  }

  async refreshToken() {
    const rt = localStorage.getItem('refreshToken');
    if (!rt) throw new Error('No refresh token');
    const r = await this.request('/auth/refresh', { method: 'POST', body: { refresh_token: rt } });
    if (r.access_token) {
      this.token = r.access_token;
      localStorage.setItem('authToken', r.access_token);
      if (r.refresh_token) localStorage.setItem('refreshToken', r.refresh_token);
    }
    return r;
  }

  async logout() {
    try { await this.request('/auth/logout', { method: 'POST' }); } finally {
      ['authToken', 'refreshToken', 'tenantSlug'].forEach(k => localStorage.removeItem(k));
      this.token = null; this.tenantSlug = null;
    }
  }

  // Users
  async getUsers(params = {}) {
    return this.request(`/admin/users?${new URLSearchParams(params)}`);
  }
  async getUser(id) { return this.request(`/admin/users/${id}`); }
  async createUser(data) { return this.request('/admin/users', { method: 'POST', body: data }); }
  async updateUser(id, data) { return this.request(`/admin/users/${id}`, { method: 'PUT', body: data }); }
  async deleteUser(id) { return this.request(`/admin/users/${id}`, { method: 'DELETE' }); }
  async lockUser(id, reason) { return this.request(`/admin/users/${id}/lock`, { method: 'POST', body: { reason } }); }
  async unlockUser(id) { return this.request(`/admin/users/${id}/unlock`, { method: 'POST' }); }
  async forcePasswordReset(id) { return this.request(`/admin/users/${id}/force-reset`, { method: 'POST' }); }
  async getUserSessions(id) { return this.request(`/admin/users/${id}/sessions`); }
  async revokeSession(userId, sessionId) { return this.request(`/admin/users/${userId}/sessions/${sessionId}`, { method: 'DELETE' }); }
  async exportUserData(id) { return this.request(`/admin/users/${id}/export`); }
  async bulkExportUsers(params = {}) { return this.request(`/admin/users/export?${new URLSearchParams(params)}`); }
  async bulkImportUsers(users) { return this.request('/admin/users/import', { method: 'POST', body: { users } }); }

  // Roles
  async getRoles() { return this.request('/admin/roles'); }
  async createRole(data) { return this.request('/admin/roles', { method: 'POST', body: data }); }
  async assignUserRole(userId, roleId) { return this.request(`/admin/users/${userId}/roles`, { method: 'POST', body: { role_id: roleId } }); }
  async removeUserRole(userId, roleId) { return this.request(`/admin/users/${userId}/roles/${roleId}`, { method: 'DELETE' }); }

  // Tenants
  async getTenants() { return this.request('/admin/tenants'); }
  async createTenant(data) { return this.request('/admin/tenants', { method: 'POST', body: data }); }

  // API Keys
  async getApiKeys() { return this.request('/admin/api-keys'); }
  async createApiKey(data) { return this.request('/admin/api-keys', { method: 'POST', body: data }); }
  async revokeApiKey(id) { return this.request(`/admin/api-keys/${id}`, { method: 'DELETE' }); }

  // Audit & Stats
  async getAuditLogs(params = {}) { return this.request(`/admin/audit-logs?${new URLSearchParams(params)}`); }
  async getStats() { return this.request('/admin/stats'); }

  // Profile
  async getProfile() { return this.request('/user/profile'); }
  async updateProfile(data) { return this.request('/user/profile', { method: 'PUT', body: data }); }
  async changePassword(current, newPw) { return this.request('/auth/change-password', { method: 'POST', body: { current_password: current, new_password: newPw } }); }
  async selfExport() { return this.request('/user/export'); }
}

const api = new AuthAPI();

// Auto-refresh token every 60s if expiring within 5min
setInterval(async () => {
  if (!api.token) return;
  try {
    const payload = JSON.parse(atob(api.token.split('.')[1]));
    if (payload.exp * 1000 - Date.now() < 300000) await api.refreshToken();
  } catch (e) { console.error('Token refresh failed:', e); }
}, 60000);
