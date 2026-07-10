-- SNR V3 — cross-session IOC correlation index.
--
-- Materializes each session's IOCs into a queryable table so indicators can be
-- correlated across incidents ("where else have we seen this?"), pivoted, and
-- browsed. This is DERIVED STATE: analysis_results.result_json remains the source
-- of truth; ioc_observations is rebuilt idempotently from it by reindexSessionIocs
-- (server/lib/ioc-index.ts) on every result write.
--
-- One row per session × distinct (type, normalized value). ioc_value_norm is the
-- correlation key: refanged (hxxp→http, [.]→., [:]→:), trimmed, lowercased — a
-- superset of the UI's iocKey (type::lower(trim(value))) so defanged variants of
-- the same indicator collapse together.

CREATE TABLE IF NOT EXISTS ioc_observations (
  id                TEXT PRIMARY KEY,
  team_id           TEXT NOT NULL REFERENCES teams(id)    ON DELETE CASCADE,
  session_id        TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  ioc_type          TEXT NOT NULL,
  ioc_value         TEXT NOT NULL,          -- as displayed (refanged form from the result)
  ioc_value_norm    TEXT NOT NULL,          -- correlation key: refang + trim + lowercase
  context           TEXT NOT NULL DEFAULT '',
  confidence        TEXT,
  is_false_positive INTEGER NOT NULL DEFAULT 0,
  created_at        BIGINT NOT NULL,
  UNIQUE (session_id, ioc_type, ioc_value_norm)
);

CREATE INDEX IF NOT EXISTS idx_ioc_obs_corr ON ioc_observations(team_id, ioc_type, ioc_value_norm);
CREATE INDEX IF NOT EXISTS idx_ioc_obs_session ON ioc_observations(session_id);

-- Backfill from the latest result version of every non-deleted, complete session.
-- FP flags are left 0 here; they re-sync from analyst_overrides on the next write.
INSERT INTO ioc_observations
  (id, team_id, session_id, ioc_type, ioc_value, ioc_value_norm, context, confidence, is_false_positive, created_at)
SELECT
  gen_random_uuid()::text,
  s.team_id,
  s.id,
  ioc.value ->> 'type',
  ioc.value ->> 'value',
  lower(trim(replace(replace(replace(ioc.value ->> 'value', '[.]', '.'), '[:]', ':'), 'hxxp', 'http'))),
  COALESCE(ioc.value ->> 'context', ''),
  ioc.value ->> 'confidence',
  0,
  s.created_at
FROM sessions s
JOIN (
  SELECT session_id, MAX(version) AS v FROM analysis_results GROUP BY session_id
) mv ON mv.session_id = s.id
JOIN analysis_results ar ON ar.session_id = s.id AND ar.version = mv.v,
  snr_json_array(ar.result_json, 'iocs') AS ioc(value)
WHERE s.status = 'complete'
  AND s.deleted_at IS NULL
  AND s.team_id IS NOT NULL
  AND ioc.value ->> 'type' IS NOT NULL
  AND ioc.value ->> 'value' IS NOT NULL
  AND trim(ioc.value ->> 'value') <> ''
ON CONFLICT (session_id, ioc_type, ioc_value_norm) DO NOTHING;
