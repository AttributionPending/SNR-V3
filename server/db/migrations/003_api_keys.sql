-- SNR V3 Phase 3 — machine authentication for the integration API.
--
-- A service_account is a non-human identity scoped to one team with a role.
-- api_keys are its credentials (allowing rotation: many keys per account). The
-- presented token is high-entropy, so we store only a SHA-256 hash for lookup.

CREATE TABLE IF NOT EXISTS service_accounts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('analyst','viewer')),
  created_by TEXT REFERENCES users(id),
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_service_accounts_team ON service_accounts(team_id);

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  service_account_id TEXT NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  prefix TEXT NOT NULL,                 -- display-only, e.g. "snr_ab12cd34"
  key_hash TEXT NOT NULL UNIQUE,        -- SHA-256 of the full token
  scopes TEXT NOT NULL DEFAULT '[]',    -- JSON array of permission scopes
  rate_limit_per_min INTEGER NOT NULL DEFAULT 60,
  created_by TEXT REFERENCES users(id),
  created_at BIGINT NOT NULL,
  last_used_at BIGINT,
  expires_at BIGINT,
  revoked_at BIGINT
);
CREATE INDEX IF NOT EXISTS idx_api_keys_account ON api_keys(service_account_id);
