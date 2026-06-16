-- SNR V3 Phase 4 — threat-intel feed ingestion.
--
-- A feed is a per-team source (TAXII 2.1, MISP, or RSS/Atom) polled on a cadence.
-- Each new item is deduplicated and turned into an analyzed session via the
-- Phase 2 job queue. feed_items records what has already been ingested.

CREATE TABLE IF NOT EXISTS feeds (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('taxii','misp','rss')),
  url TEXT NOT NULL,
  auth_token TEXT,                      -- bearer/API key for the source (sensitive)
  config TEXT NOT NULL DEFAULT '{}',    -- JSON: type-specific (e.g. TAXII collectionId)
  audience TEXT NOT NULL DEFAULT 'soc', -- audience used when analyzing items
  tags TEXT NOT NULL DEFAULT '[]',      -- JSON array applied to created sessions
  cadence_minutes INTEGER NOT NULL DEFAULT 60,
  max_items INTEGER NOT NULL DEFAULT 5, -- per-poll cap (bounds analysis cost)
  enabled INTEGER NOT NULL DEFAULT 1,
  last_polled_at BIGINT,
  last_status TEXT,
  created_by TEXT REFERENCES users(id),
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_feeds_team ON feeds(team_id);
CREATE INDEX IF NOT EXISTS idx_feeds_enabled ON feeds(enabled, last_polled_at);

CREATE TABLE IF NOT EXISTS feed_items (
  id TEXT PRIMARY KEY,
  feed_id TEXT NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
  source_id TEXT NOT NULL,              -- stable id from the source (guid/stix id/uuid)
  content_hash TEXT NOT NULL,
  session_id TEXT REFERENCES sessions(id) ON DELETE SET NULL,
  created_at BIGINT NOT NULL,
  UNIQUE (feed_id, source_id)
);
CREATE INDEX IF NOT EXISTS idx_feed_items_feed ON feed_items(feed_id);
