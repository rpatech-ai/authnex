-- schema.sql - Complete D1 Authentication Platform Schema
-- Multi-tenant architecture with RBAC, audit logging, and performance optimizations

-- Core Tables
CREATE TABLE IF NOT EXISTS tenants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT UNIQUE NOT NULL COLLATE NOCASE,
  name TEXT NOT NULL,
  status TEXT DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'trial')),
  settings TEXT DEFAULT '{}', -- JSON: branding, features, limits
  plan TEXT DEFAULT 'free',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  suspended_at DATETIME,
  trial_ends_at DATETIME,
  metadata TEXT DEFAULT '{}' -- JSON: custom fields
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  status TEXT DEFAULT 'pending' CHECK(status IN ('active', 'pending', 'locked', 'deleted')),
  email_verified BOOLEAN DEFAULT 0,
  email_verified_at DATETIME,
  locked_reason TEXT,
  locked_at DATETIME,
  locked_by INTEGER,
  failed_attempts INTEGER DEFAULT 0,
  last_failed_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  deleted_at DATETIME,
  metadata TEXT DEFAULT '{}' -- JSON: profile data
);

CREATE TABLE IF NOT EXISTS roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  permissions TEXT NOT NULL, -- JSON array of permissions
  is_system BOOLEAN DEFAULT 0, -- Cannot be deleted
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  UNIQUE(tenant_id, name)
);

-- Junction Tables
CREATE TABLE IF NOT EXISTS user_tenants (
  user_id INTEGER NOT NULL,
  tenant_id INTEGER NOT NULL,
  joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  invited_by INTEGER,
  invite_accepted_at DATETIME,
  is_primary BOOLEAN DEFAULT 0,
  settings TEXT DEFAULT '{}', -- JSON: user-specific tenant settings
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (invited_by) REFERENCES users(id),
  PRIMARY KEY (user_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS user_roles (
  user_id INTEGER NOT NULL,
  tenant_id INTEGER NOT NULL,
  role_id INTEGER NOT NULL,
  granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  granted_by INTEGER,
  expires_at DATETIME,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
  FOREIGN KEY (granted_by) REFERENCES users(id),
  PRIMARY KEY (user_id, tenant_id, role_id)
);

-- Token Management
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id TEXT PRIMARY KEY, -- UUID
  user_id INTEGER NOT NULL,
  tenant_id INTEGER,
  token_hash TEXT UNIQUE NOT NULL, -- SHA256 of token
  family_id TEXT NOT NULL, -- For rotation tracking
  expires_at DATETIME NOT NULL,
  last_used_at DATETIME,
  ip_address TEXT,
  user_agent TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  revoked_at DATETIME,
  revoked_reason TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY, -- UUID
  tenant_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  key_hash TEXT UNIQUE NOT NULL, -- SHA256 of key
  permissions TEXT DEFAULT '[]', -- JSON array
  last_used_at DATETIME,
  expires_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  created_by INTEGER NOT NULL,
  revoked_at DATETIME,
  ip_whitelist TEXT, -- JSON array of IPs
  rate_limit INTEGER DEFAULT 1000, -- Requests per hour
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Email Verification & Password Reset
CREATE TABLE IF NOT EXISTS verification_tokens (
  id TEXT PRIMARY KEY, -- UUID
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('email', 'password', 'invite')),
  token_hash TEXT UNIQUE NOT NULL,
  expires_at DATETIME NOT NULL,
  used_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  metadata TEXT DEFAULT '{}', -- JSON: additional context
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Sessions (backup for JWT)
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, -- UUID
  user_id INTEGER NOT NULL,
  tenant_id INTEGER,
  token_hash TEXT UNIQUE NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Audit Logging
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER,
  user_id INTEGER,
  action TEXT NOT NULL, -- login, logout, password_change, etc.
  resource_type TEXT, -- user, role, tenant, etc.
  resource_id TEXT,
  changes TEXT, -- JSON: before/after values
  ip_address TEXT,
  user_agent TEXT,
  success BOOLEAN DEFAULT 1,
  error_message TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Rate Limiting (backup for KV)
CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY, -- ip:endpoint or user:endpoint
  count INTEGER DEFAULT 1,
  window_start DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Performance Indexes

CREATE INDEX idx_user_tenants_user ON user_tenants(user_id);
CREATE INDEX idx_user_tenants_tenant ON user_tenants(tenant_id);
CREATE INDEX idx_user_roles_user_tenant ON user_roles(user_id, tenant_id);
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family_id);
CREATE INDEX idx_audit_logs_tenant_date ON audit_logs(tenant_id, created_at DESC);
CREATE INDEX idx_audit_logs_user_date ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_rate_limits_window ON rate_limits(window_start);


CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX idx_verification_tokens_user ON verification_tokens(user_id);
CREATE INDEX idx_sessions_user ON sessions(user_id);
-- Triggers for updated_at
CREATE TRIGGER update_tenants_timestamp 
AFTER UPDATE ON tenants 
BEGIN 
  UPDATE tenants SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_users_timestamp 
AFTER UPDATE ON users 
BEGIN 
  UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Initial System Data
INSERT OR IGNORE INTO tenants (id, slug, name, status, settings) 
VALUES (1, 'system', 'System Tenant', 'active', '{"features":["all"]}');

-- Default roles for each tenant (via application logic)
-- admin: full access
-- user: basic access
-- readonly: view only

-- Cleanup old data (run periodically via cron trigger)
-- DELETE FROM audit_logs WHERE created_at < datetime('now', '-90 days');
-- DELETE FROM verification_tokens WHERE expires_at < datetime('now', '-1 day');
-- DELETE FROM sessions WHERE expires_at < datetime('now');
-- DELETE FROM rate_limits WHERE window_start < datetime('now', '-1 hour');
-- DELETE FROM refresh_tokens WHERE expires_at < datetime('now', '-30 days');