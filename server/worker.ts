/**
 * SNR V3 analysis worker.
 *
 * A separate process from the API. Consumes analysis jobs from pg-boss and runs
 * the LLM pipeline, streaming progress into job_events (which the API tails for
 * SSE). Running it apart from the API means an API restart never interrupts an
 * in-flight analysis, and analyses run concurrently without blocking HTTP.
 *
 * Start: `npm run worker` (or `tsx server/worker.ts`). In dev, `npm run dev`
 * launches it alongside the API.
 */
import { config } from 'dotenv';
import path from 'path';
import http from 'http';
import { fileURLToPath } from 'url';
import { initDb, closeDb } from './db/database.js';
import { startBoss, stopBoss, ANALYSIS_QUEUE, type AnalysisJobData } from './jobs/queue.js';
import { runAnalysisJob } from './jobs/analysis-handler.js';
import { registry } from './lib/metrics.js';
import logger from './lib/logger.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
config({ override: false, path: path.resolve(__dirname, '../.env') });

const CONCURRENCY = parseInt(process.env.ANALYSIS_WORKER_CONCURRENCY ?? '2', 10);
const METRICS_PORT = parseInt(process.env.WORKER_METRICS_PORT ?? '9091', 10);

async function start() {
  // Ensure schema exists (idempotent — safe even if the API already migrated).
  await initDb();

  const boss = await startBoss();

  await boss.work<AnalysisJobData>(
    ANALYSIS_QUEUE,
    { localConcurrency: CONCURRENCY },
    async (jobs) => {
      for (const job of jobs) {
        logger.info({ jobId: job.id, sessionId: job.data.sessionId }, 'Processing analysis job');
        await runAnalysisJob(job.id, job.data);
      }
    },
  );

  logger.info({ concurrency: CONCURRENCY }, `Analysis worker started, consuming "${ANALYSIS_QUEUE}"`);

  // Lightweight metrics endpoint so Prometheus can scrape worker-side counters
  // (job success/fail, durations) separately from the API.
  const metricsServer = http.createServer(async (req, res) => {
    if (req.url === '/metrics') {
      const token = process.env.METRICS_TOKEN;
      if (token && req.headers.authorization !== `Bearer ${token}`) {
        res.statusCode = 401;
        res.end();
        return;
      }
      res.setHeader('Content-Type', registry.contentType);
      res.end(await registry.metrics());
    } else if (req.url === '/healthz') {
      res.end('ok');
    } else {
      res.statusCode = 404;
      res.end();
    }
  });
  metricsServer.listen(METRICS_PORT, '0.0.0.0', () => {
    logger.info(`Worker metrics on :${METRICS_PORT}/metrics`);
  });

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'Worker shutting down…');
    metricsServer.close();
    try {
      await stopBoss();
      await closeDb();
    } catch (err) {
      logger.error({ err }, 'Error during worker shutdown');
    }
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

start().catch((err) => {
  logger.fatal({ err }, 'Failed to start worker');
  process.exit(1);
});
