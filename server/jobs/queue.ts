/**
 * pg-boss job queue (Postgres-backed) for asynchronous analysis.
 *
 * Both the API process (enqueues jobs, reads queue stats) and the worker process
 * (consumes jobs) call startBoss() at startup. pg-boss persists jobs in its own
 * `pgboss` schema in the same database, so jobs survive restarts and are retried.
 */
import { PgBoss } from 'pg-boss';
import { readSecret } from '../lib/secrets.js';
import logger from '../lib/logger.js';

export const ANALYSIS_QUEUE = 'analysis';

/** Payload for an analysis job. Carries the identity/context the worker needs
 * (there is no HTTP request in the worker process). */
export interface AnalysisJobData {
  sessionId: string;
  siemClean: string;
  textClean: string;
  logClean: string;
  audience: string;
  inputHash: string;
  auditAction: 'analysis_complete' | 'analysis_rerun';
  teamId: string;
  /** Owning user id, or null for service-account (API) submissions. */
  userId: string | null;
  displayName: string;
  /** Optional callback URL POSTed on terminal job state (integration API). */
  webhookUrl?: string | null;
}

let boss: PgBoss | undefined;
let starting: Promise<PgBoss> | undefined;

/** Start (once) and return the pg-boss instance, ensuring the queue exists. */
export async function startBoss(): Promise<PgBoss> {
  if (boss) return boss;
  if (starting) return starting;

  starting = (async () => {
    const connectionString = readSecret('DATABASE_URL');
    if (!connectionString) {
      throw new Error('DATABASE_URL must be set to use the job queue.');
    }
    const instance = new PgBoss({
      connectionString,
      // Keep finished jobs around briefly for status lookups, then auto-delete.
      // (Per-send options can override.)
    });
    instance.on('error', (err) => logger.error({ err }, 'pg-boss error'));
    await instance.start();
    await instance.createQueue(ANALYSIS_QUEUE);
    boss = instance;
    logger.info('Job queue (pg-boss) started');
    return instance;
  })();

  return starting;
}

/** Enqueue an analysis job; returns the job id (used as the SSE stream key). */
export async function enqueueAnalysis(data: AnalysisJobData): Promise<string> {
  const b = await startBoss();
  const jobId = await b.send(ANALYSIS_QUEUE, data, {
    retryLimit: 2,
    retryDelay: 5,
    expireInSeconds: parseInt(process.env.ANALYSIS_JOB_EXPIRE_SECONDS ?? '900', 10),
    // Keep the job row for a while after completion for status polling.
    retentionSeconds: 24 * 60 * 60,
  });
  if (!jobId) {
    throw new Error('Failed to enqueue analysis job');
  }
  return jobId;
}

/** Queue depth stats for metrics/observability. */
export async function getQueueStats(): Promise<{ queued: number; active: number; total: number }> {
  const b = await startBoss();
  const q = await b.getQueueStats(ANALYSIS_QUEUE);
  return { queued: q.queuedCount, active: q.activeCount, total: q.totalCount };
}

export async function stopBoss(): Promise<void> {
  if (boss) {
    await boss.stop({ graceful: true });
    boss = undefined;
    starting = undefined;
  }
}
