-- SNR V3 — cross-session detection-rule index (detection coverage).
--
-- Materializes each session's detection_rules into a queryable table so rule
-- coverage can be aggregated across incidents and mapped to ATT&CK ("which
-- techniques have we written rules for, and where are the gaps?").
--
-- This is DERIVED STATE, exactly like ioc_observations (008): result_json
-- remains the source of truth and reindexSessionDetectionRules
-- (server/lib/detection-index.ts) rebuilds a session's rows idempotently on
-- every result write. The table can be dropped and repopulated at any time.
--
-- One row per session x distinct (rule_type, rule_name, rule_hash). rule_hash is
-- a sha256 of the whitespace-normalized rule body, so the same rule recurring
-- across sessions can be counted once (distinct) as well as in total.
-- technique_id is the ATT&CK id parsed out of the rule's related_technique, or
-- NULL when the rule is unmapped.

CREATE TABLE IF NOT EXISTS detection_rule_observations (
  id           TEXT PRIMARY KEY,
  team_id      TEXT NOT NULL REFERENCES teams(id)    ON DELETE CASCADE,
  session_id   TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  rule_type    TEXT NOT NULL,                  -- sigma | yara | suricata
  rule_name    TEXT NOT NULL,
  rule_hash    TEXT NOT NULL,                  -- sha256 of the normalized rule body
  description  TEXT NOT NULL DEFAULT '',
  source       TEXT NOT NULL DEFAULT 'generated',  -- extracted | generated
  confidence   TEXT,
  technique_id TEXT,                           -- ATT&CK id, or NULL when unmapped
  created_at   BIGINT NOT NULL,
  UNIQUE (session_id, rule_type, rule_name, rule_hash)
);

CREATE INDEX IF NOT EXISTS idx_detection_rules_technique ON detection_rule_observations(team_id, technique_id);
CREATE INDEX IF NOT EXISTS idx_detection_rules_hash      ON detection_rule_observations(team_id, rule_hash);
CREATE INDEX IF NOT EXISTS idx_detection_rules_session   ON detection_rule_observations(session_id);

-- Backfill from the latest result version of every non-deleted, complete
-- session, so coverage is populated the moment this ships.
--
-- The technique id is parsed out of related_technique with the same rule the
-- application uses: the first T#### or T####.### token, uppercased. Postgres
-- substring() with a POSIX class returns NULL when there is no match, which is
-- exactly the "unmapped rule" case.
INSERT INTO detection_rule_observations
  (id, team_id, session_id, rule_type, rule_name, rule_hash, description, source, confidence, technique_id, created_at)
SELECT
  gen_random_uuid()::text,
  s.team_id,
  s.id,
  LOWER(rule.value ->> 'rule_type'),
  rule.value ->> 'rule_name',
  encode(sha256(convert_to(regexp_replace(COALESCE(rule.value ->> 'rule_content', ''), '\s+', ' ', 'g'), 'UTF8')), 'hex'),
  COALESCE(rule.value ->> 'description', ''),
  COALESCE(rule.value ->> 'source', 'generated'),
  rule.value ->> 'confidence',
  UPPER(substring(COALESCE(rule.value ->> 'related_technique', '') from 'T[0-9]{4}(?:\.[0-9]{3})?')),
  s.created_at
FROM sessions s
JOIN (
  SELECT session_id, MAX(version) AS v FROM analysis_results GROUP BY session_id
) mv ON mv.session_id = s.id
JOIN analysis_results ar ON ar.session_id = s.id AND ar.version = mv.v,
  snr_json_array(ar.result_json, 'detection_rules') AS rule(value)
WHERE s.status = 'complete'
  AND s.deleted_at IS NULL
  AND s.team_id IS NOT NULL
  AND rule.value ->> 'rule_type' IS NOT NULL
  AND rule.value ->> 'rule_name' IS NOT NULL
  AND trim(rule.value ->> 'rule_name') <> ''
ON CONFLICT (session_id, rule_type, rule_name, rule_hash) DO NOTHING;
