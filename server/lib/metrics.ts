/**
 * Prometheus metrics for on-prem monitoring. Exposed at GET /metrics.
 * Default Node process metrics plus a few SNR-specific counters/histograms.
 */
import { Registry, collectDefaultMetrics, Counter, Histogram } from 'prom-client';

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
