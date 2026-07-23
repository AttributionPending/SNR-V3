-- SNR V3 — per-case entity exclusions.
--
-- A case's IOCs / actors / techniques come from two places: pinned members
-- (case_iocs / case_actors / case_techniques) and entities DERIVED from the
-- case's linked sessions. Pinned members can simply be unpinned, but a derived
-- entity would reappear on every load, so "remove from case" records an
-- exclusion here instead. Exclusions are per-case only: the session stays
-- linked, the underlying intel is untouched, and other cases are unaffected.
--
-- Re-adding (pinning) the same entity clears its exclusion, so remove/add is
-- symmetric. entity_key is:
--   ioc       -> '<ioc_type>::<ioc_value_norm>'
--   actor     -> threat_actors.id
--   technique -> ATT&CK technique id (e.g. T1566.001)

CREATE TABLE IF NOT EXISTS case_exclusions (
  case_id     TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  entity_type TEXT NOT NULL CHECK (entity_type IN ('ioc','actor','technique')),
  entity_key  TEXT NOT NULL,
  excluded_at BIGINT NOT NULL,
  excluded_by TEXT REFERENCES users(id),
  PRIMARY KEY (case_id, entity_type, entity_key)
);

CREATE INDEX IF NOT EXISTS idx_case_exclusions_case ON case_exclusions(case_id, entity_type);
