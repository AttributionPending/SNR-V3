/**
 * Prometheus metrics for on-prem monitoring. Exposed at GET /metrics.
 * Default Node process metrics plus a few SNR-specific counters/histograms.
 */
import { Registry, collectDefaultMetrics, Counter, Histogram, Gauge } from 'prom-client';

export const registry = new Registry();
collectDefaultMetrics({ register: registry, prefix: 'snr_' });

export const httpRequestsTotal = new Counter({
  name: 'snr_http_requests_total',
  help: 'Total HTTP requests handled, labeled by method and status code.',
  labelNames: ['method', 'status'] as const,
  registers: [registry],
});

export const analysisRunsTotal = new Counter({
  name: 'snr_analysis_runs_total',
  help: 'Total analysis runs, labeled by result (success|failed) and kind (analyze|rerun).',
  labelNames: ['result', 'kind'] as const,
  registers: [registry],
});

export const analysisDurationSeconds = new Histogram({
  name: 'snr_analysis_duration_seconds',
  help: 'Wall-clock duration of an analysis run in seconds.',
  buckets: [5, 10, 20, 30, 45, 60, 90, 120, 180, 300, 600],
  registers: [registry],
});

// Async-job (pg-boss) metrics. The queue-depth gauge is set via a collect hook
// on the API process; the counter/histogram are incremented in the worker.
export const analysisQueueDepth = new Gauge({
  name: 'snr_analysis_queue_depth',
  help: 'Analysis jobs in the queue, labeled by state (queued|active).',
  labelNames: ['state'] as const,
  registers: [registry],
});

export const jobsProcessedTotal = new Counter({
  name: 'snr_jobs_processed_total',
  help: 'Total async jobs processed by the worker, labeled by result (success|failed).',
  labelNames: ['result'] as const,
  registers: [registry],
});
