-- SNR V3 — analyst annotations on first-class entities (IOCs and threat actors).
--
-- Sessions have analyst_notes and cases have case_log, but there was no way to
-- attach a comment to an indicator or an actor. entity_annotations is a
-- team-scoped comment thread keyed by a canonical entity id:
--   ioc   → iocIndexKey(type, value) = `${type}::${normalized value}`
--   actor → the threat_actors.id
-- The key is always computed server-side (server/lib/ioc-index.ts) so clients
-- send raw (type,value) or actor_id and never need to replicate normalization.

CREATE TABLE IF NOT EXISTS entity_annotations (
  id           TEXT PRIMARY KEY,
  team_id      TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  entity_type  TEXT NOT NULL CHECK (entity_type IN ('ioc','actor')),
  entity_key   TEXT NOT NULL,
  entity_label TEXT NOT NULL DEFAULT '',
  user_id      TEXT REFERENCES users(id),
  author_name  TEXT NOT NULL,
  content      TEXT NOT NULL,
  created_at   BIGINT NOT NULL,
  updated_at   BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entity_annot ON entity_annotations(team_id, entity_type, entity_key, created_at);
