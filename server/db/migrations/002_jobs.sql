-- SNR V3 Phase 2 — async analysis jobs.
--
-- pg-boss manages its own schema (the `pgboss` schema) when it starts. This
-- migration adds only the application-level streaming channel: the worker writes
-- analysis progress events here, and the API tails them to stream Server-Sent
-- Events to the browser (the two run in separate processes).

CREATE TABLE IF NOT EXISTS job_events (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  job_id TEXT NOT NULL,
  event TEXT NOT NULL,          -- 'status' | 'chunk' | 'complete' | 'error'
  data TEXT NOT NULL,           -- JSON payload (already stringified)
  created_at BIGINT NOT NULL
);

-- The API streamer polls "events for this job after id N", in order.
CREATE INDEX IF NOT EXISTS idx_job_events_job ON job_events(job_id, id);

-- For retention cleanup of old/terminal job event streams.
CREATE INDEX IF NOT EXISTS idx_job_events_created ON job_events(created_at);
