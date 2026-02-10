-- schema-v2.sql — Plans, Usage Tracking, Billing
-- Sprint 3: Self-service signup & customer dashboard

CREATE TABLE IF NOT EXISTS plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  max_users INTEGER DEFAULT 100,
  max_api_calls INTEGER DEFAULT 10000,
  max_tenants INTEGER DEFAULT 1,
  features TEXT DEFAULT '[]',
  price_monthly INTEGER DEFAULT 0,
  price_yearly INTEGER DEFAULT 0,
  is_active BOOLEAN DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS usage_tracking (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER NOT NULL,
  period TEXT NOT NULL,
  api_calls INTEGER DEFAULT 0,
  logins INTEGER DEFAULT 0,
  registrations INTEGER DEFAULT 0,
  token_refreshes INTEGER DEFAULT 0,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  UNIQUE(tenant_id, period)
);

CREATE TABLE IF NOT EXISTS billing_status (
  tenant_id INTEGER PRIMARY KEY,
  plan_id INTEGER NOT NULL,
  status TEXT DEFAULT 'active' CHECK(status IN ('active', 'past_due', 'cancelled', 'trial')),
  trial_ends_at DATETIME,
  current_period_start DATETIME,
  current_period_end DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (plan_id) REFERENCES plans(id)
);

-- Default plans
INSERT OR IGNORE INTO plans (id, name, display_name, max_users, max_api_calls, features, price_monthly)
VALUES
  (1, 'free', 'Free', 50, 5000, '["registration","login","basic_rbac"]', 0),
  (2, 'starter', 'Starter', 500, 50000, '["registration","login","basic_rbac","webhooks","api_keys"]', 29),
  (3, 'pro', 'Professional', 5000, 500000, '["all"]', 99),
  (4, 'enterprise', 'Enterprise', -1, -1, '["all"]', 0);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_usage_tenant_period ON usage_tracking(tenant_id, period);
CREATE INDEX IF NOT EXISTS idx_billing_plan ON billing_status(plan_id);
