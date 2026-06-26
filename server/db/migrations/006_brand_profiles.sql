-- SNR V3 — white-label brand profiles.
--
-- A brand profile is a per-team, reusable email identity: a partial EmailTheme
-- (visual white-labeling) + a sender config (From/Reply-To/CC/BCC/preheader/
-- subject). Sessions may point at a profile; otherwise the team's default
-- profile (or the built-in SNR theme) is used.

CREATE TABLE IF NOT EXISTS brand_profiles (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  is_default INTEGER NOT NULL DEFAULT 0,
  theme TEXT NOT NULL DEFAULT '{}',   -- JSON: Partial<EmailTheme>
  sender TEXT NOT NULL DEFAULT '{}',  -- JSON: EmailSender
  created_by TEXT REFERENCES users(id),
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_brand_profiles_team ON brand_profiles(team_id);

-- Per-session brand selection (null = team default / built-in SNR theme).
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS brand_profile_id TEXT REFERENCES brand_profiles(id) ON DELETE SET NULL;
