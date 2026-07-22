-- SNR V3 — analyst-curated (manual) indicators.
--
-- Indicators an analyst wants to track that are NOT derived from a report. Unlike
-- ioc_observations (derived state, rebuilt from analysis_results on every write and
-- requiring a session_id), these are first-class curated rows with no session tie.
-- They are MERGED into the indicator browse/holdings views by (team, type, norm) so
-- they appear alongside report-derived IOCs, flagged `manual`, with a 0 incident
-- count until a report also references them. ioc_value_norm is the same correlation
-- key used by ioc_observations (refang + trim + lowercase) so a manual indicator and
-- a later report observation of the same value collapse to one row.

CREATE TABLE IF NOT EXISTS manual_iocs (
  id             TEXT PRIMARY KEY,
  team_id        TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  ioc_type       TEXT NOT NULL,
  ioc_value      TEXT NOT NULL,          -- as entered (refanged for display)
  ioc_value_norm TEXT NOT NULL,          -- correlation key: refang + trim + lowercase
  context        TEXT NOT NULL DEFAULT '',
  confidence     TEXT,
  source         TEXT NOT NULL DEFAULT '',
  created_by     TEXT REFERENCES users(id) ON DELETE SET NULL,
  author_name    TEXT NOT NULL DEFAULT '',
  created_at     BIGINT NOT NULL,
  updated_at     BIGINT NOT NULL,
  UNIQUE (team_id, ioc_type, ioc_value_norm)
);

CREATE INDEX IF NOT EXISTS idx_manual_iocs_corr ON manual_iocs(team_id, ioc_type, ioc_value_norm);
