-- SNR V3 — user-configurable indicator enrichment providers.
--
-- A provider is a per-team external lookup source an admin (or team lead) adds
-- from the Admin panel — either a built-in catalog preset (VirusTotal,
-- AbuseIPDB, …) or a Custom HTTP provider whose URL/headers/response mappings
-- the operator defines. Both kinds are driven by the SAME `config` JSON, so
-- there is one executor rather than a code path per vendor.
--
-- Mirrors the feeds conventions (004_feeds.sql): per-team, admin/lead managed,
-- secret stored server-side and never returned by the list endpoint.
--
-- Nothing is enabled by default: with no rows, no indicator value leaves the
-- network.

CREATE TABLE IF NOT EXISTS enrichment_providers (
  id           TEXT PRIMARY KEY,
  team_id      TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  kind         TEXT NOT NULL,                 -- catalog id ('virustotal', …) or 'custom'
  enabled      INTEGER NOT NULL DEFAULT 1,
  api_key      TEXT,                          -- sensitive: never returned to the client
  config       TEXT NOT NULL DEFAULT '{}',    -- JSON: supports[], url, headers, summary, facts[], link, notFound[]
  last_status  TEXT,
  last_used_at BIGINT,
  created_by   TEXT REFERENCES users(id),
  created_at   BIGINT NOT NULL,
  updated_at   BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enrichment_providers_team ON enrichment_providers(team_id, enabled);

-- Response cache so re-opening an indicator card doesn't re-bill the provider's
-- API (VirusTotal's free tier is ~4 requests/minute). Keyed by the canonical
-- normalized indicator so defanged variants share an entry.
CREATE TABLE IF NOT EXISTS enrichment_cache (
  provider_id    TEXT NOT NULL REFERENCES enrichment_providers(id) ON DELETE CASCADE,
  ioc_type       TEXT NOT NULL,
  ioc_value_norm TEXT NOT NULL,
  payload        TEXT NOT NULL,               -- JSON EnrichmentResult
  fetched_at     BIGINT NOT NULL,
  PRIMARY KEY (provider_id, ioc_type, ioc_value_norm)
);
CREATE INDEX IF NOT EXISTS idx_enrichment_cache_fetched ON enrichment_cache(fetched_at);
