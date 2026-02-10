-- schema-v4.sql — 2FA (TOTP) & WebAuthn/Passkeys
-- Sprint 6: Second factor authentication & passwordless

CREATE TABLE IF NOT EXISTS totp_secrets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER UNIQUE NOT NULL,
  secret TEXT NOT NULL,
  algorithm TEXT DEFAULT 'SHA1',
  digits INTEGER DEFAULT 6,
  period INTEGER DEFAULT 30,
  verified BOOLEAN DEFAULT 0,
  backup_codes TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  verified_at DATETIME,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  credential_id TEXT UNIQUE NOT NULL,
  public_key TEXT NOT NULL,
  counter INTEGER DEFAULT 0,
  device_name TEXT,
  transports TEXT DEFAULT '[]',
  aaguid TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_used_at DATETIME,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
  id TEXT PRIMARY KEY,
  user_id INTEGER,
  challenge TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('registration', 'authentication')),
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_totp_user ON totp_secrets(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credential ON webauthn_credentials(credential_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user ON webauthn_challenges(user_id);
