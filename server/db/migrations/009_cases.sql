-- SNR V3 — Case management (investigations).
--
-- A Case is a first-class investigation that groups multiple sessions over time,
-- carries a workflow state (status/priority/assignee), and keeps an append-only
-- investigation log. Threat actors and IOCs are DERIVED from the case's linked
-- sessions (via session_threat_actors and the ioc_observations index) rather than
-- pinned here, keeping the model focused. Deleting a case never deletes sessions —
-- only the join rows and the log cascade.
--
-- Mirrors the threat_actors conventions: TEXT uuid PKs, epoch-ms BIGINT timestamps,
-- team_id/created_by FKs, CHECK enums, cascade join tables indexed both directions.

CREATE TABLE IF NOT EXISTS cases (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  summary    TEXT NOT NULL DEFAULT '',
  status     TEXT NOT NULL DEFAULT 'open'   CHECK (status   IN ('open','monitoring','closed')),
  priority   TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('critical','high','medium','low')),
  assignee   TEXT REFERENCES users(id),
  team_id    TEXT REFERENCES teams(id),
  created_by TEXT REFERENCES users(id),
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_team ON cases(team_id);

-- M:N — a session can inform several investigations.
CREATE TABLE IF NOT EXISTS case_sessions (
  case_id    TEXT NOT NULL REFERENCES cases(id)    ON DELETE CASCADE,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  added_at   BIGINT NOT NULL,
  added_by   TEXT REFERENCES users(id),
  PRIMARY KEY (case_id, session_id)
);
CREATE INDEX IF NOT EXISTS idx_case_sessions_session ON case_sessions(session_id);

-- Append-only investigation log / timeline.
CREATE TABLE IF NOT EXISTS case_log (
  id          TEXT PRIMARY KEY,
  case_id     TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  user_id     TEXT REFERENCES users(id),
  author_name TEXT NOT NULL,
  entry_type  TEXT NOT NULL DEFAULT 'note'
    CHECK (entry_type IN ('note','status_change','session_added','session_removed','created')),
  content     TEXT NOT NULL DEFAULT '',
  created_at  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_case_log_case ON case_log(case_id, created_at);
