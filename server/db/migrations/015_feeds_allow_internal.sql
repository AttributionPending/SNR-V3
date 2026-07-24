-- SNR V3 — per-feed opt-in for internal (self-hosted) sources.
--
-- Feed URLs are admin-supplied, so feed polling now runs through the same
-- guarded egress as enrichment (server/lib/enrichment/egress.ts): public https
-- only, with loopback and cloud-metadata destinations refused outright.
--
-- MISP and TAXII servers are commonly self-hosted on private networks, so a
-- feed can be explicitly marked internal. That permits RFC1918 / CGNAT /
-- unique-local destinations and plain http FOR THAT FEED ONLY. Loopback and
-- 169.254.169.254 stay blocked regardless.
--
-- Defaults to 0 so existing feeds keep the strict public-https policy.

ALTER TABLE feeds ADD COLUMN IF NOT EXISTS allow_internal INTEGER NOT NULL DEFAULT 0;
