-- SNR V3 — first-class case members (the investigative workbench).
--
-- Beyond linking sessions, an analyst can pin actors, ATT&CK techniques, and
-- indicators DIRECTLY to a case. Case detail MERGES these with the entities
-- derived from the case's linked sessions, flagging the pinned ones so they can
-- be removed. Deleting a case cascades these join rows; the referenced actors and
-- sessions are never touched. Mirrors the case_sessions conventions.

CREATE TABLE IF NOT EXISTS case_actors (
  case_id         TEXT NOT NULL REFERENCES cases(id)         ON DELETE CASCADE,
  threat_actor_id TEXT NOT NULL REFERENCES threat_actors(id) ON DELETE CASCADE,
  added_at        BIGINT NOT NULL,
  added_by        TEXT REFERENCES users(id),
  PRIMARY KEY (case_id, threat_actor_id)
);
CREATE INDEX IF NOT EXISTS idx_case_actors_actor ON case_actors(threat_actor_id);

CREATE TABLE IF NOT EXISTS case_techniques (
  case_id        TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  technique_id   TEXT NOT NULL,
  technique_name TEXT NOT NULL DEFAULT '',
  tactic         TEXT NOT NULL DEFAULT '',
  added_at       BIGINT NOT NULL,
  added_by       TEXT REFERENCES users(id),
  PRIMARY KEY (case_id, technique_id)
);

CREATE TABLE IF NOT EXISTS case_iocs (
  case_id        TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  ioc_type       TEXT NOT NULL,
  ioc_value      TEXT NOT NULL,
  ioc_value_norm TEXT NOT NULL,          -- refang + trim + lowercase (same key as ioc_observations)
  context        TEXT NOT NULL DEFAULT '',
  added_at       BIGINT NOT NULL,
  added_by       TEXT REFERENCES users(id),
  PRIMARY KEY (case_id, ioc_type, ioc_value_norm)
);

-- Expand the investigation-log entry types to cover the new member actions.
ALTER TABLE case_log DROP CONSTRAINT IF EXISTS case_log_entry_type_check;
ALTER TABLE case_log ADD CONSTRAINT case_log_entry_type_check CHECK (entry_type IN (
  'note','status_change','session_added','session_removed','created',
  'actor_added','actor_removed','technique_added','technique_removed','ioc_added','ioc_removed'
));
