/**
 * Cross-process streaming channel for analysis jobs.
 *
 * The worker writes progress events (status / chunk / complete / error) into the
 * `job_events` table via JobEventWriter. The API process tails those rows for a
 * given job id and forwards them to the browser as Server-Sent Events — in the
 * exact event format the existing frontend already consumes, so the streaming UX
 * is unchanged even though the work now happens in a separate process.
 */
import type { Response } from 'express';
import { getDb } from '../db/database.js';
import logger from '../lib/logger.js';

const TERMINAL = new Set(['complete', 'error']);

/** Append a single event row for a job. */
async function writeJobEvent(jobId: string, event: string, data: unknown): Promise<void> {
  const db = getDb();
  await db
    .prepare('INSERT INTO job_events (job_id, event, data, created_at) VALUES (?, ?, ?, ?)')
    .run(jobId, event, JSON.stringify(data), Date.now());
}

/**
 * Ordered, buffered writer used by the worker. Chunk text is coalesced and
 * flushed (as one 'chunk' event) on a size threshold or before any status/
 * terminal event, to keep row volume sane without harming streaming smoothness.
 * All writes are serialized through a promise chain to guarantee ordering.
 */
export class JobEventWriter {
  private buf = '';
  private chain: Promise<void> = Promise.resolve();
  private readonly threshold = 256;

  constructor(private readonly jobId: string) {}

  private enqueue(fn: () => Promise<void>): Promise<void> {
    this.chain = this.chain.then(fn).catch((err) => {
      logger.error({ err, jobId: this.jobId }, 'Failed to write job event');
    });
    return this.chain;
  }

  /** Append streamed LLM text (coalesced). */
  pushChunk(text: string): void {
    if (!text) return;
    this.buf += text;
    if (this.buf.length >= this.threshold) this.flushBuffer();
  }

  private flushBuffer(): void {
    if (!this.buf) return;
    const text = this.buf;
    this.buf = '';
    void this.enqueue(() => writeJobEvent(this.jobId, 'chunk', { text }));
  }

  status(message: string, phase: number): Promise<void> {
    this.flushBuffer();
    return this.enqueue(() => writeJobEvent(this.jobId, 'status', { message, phase }));
  }

  complete(data: unknown): Promise<void> {
    this.flushBuffer();
    return this.enqueue(() => writeJobEvent(this.jobId, 'complete', data));
  }

  error(message: string): Promise<void> {
    this.flushBuffer();
    return this.enqueue(() => writeJobEvent(this.jobId, 'error', { error: message }));
  }

  /** Ensure all buffered/queued writes have been persisted. */
  drain(): Promise<void> {
    this.flushBuffer();
    return this.chain;
  }
}

/**
 * Tail job_events for `jobId` and forward each as an SSE message to `res`, until
 * a terminal event (complete/error) is seen, the client disconnects, or the
 * timeout elapses. Catches up on any events written before the stream attached.
 */
export async function streamJobToResponse(
  res: Response,
  jobId: string,
  opts: { timeoutMs?: number; pollMs?: number } = {},
): Promise<void> {
  const timeoutMs = opts.timeoutMs ?? 15 * 60 * 1000;
  const pollMs = opts.pollMs ?? 200;
  const db = getDb();

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  let clientGone = false;
  res.on('close', () => {
    clientGone = true;
  });

  let lastId = 0;
  const deadline = Date.now() + timeoutMs;

  while (!clientGone && Date.now() < deadline) {
    const rows = (await db
      .prepare('SELECT id, event, data FROM job_events WHERE job_id = ? AND id > ? ORDER BY id ASC')
      .all(jobId, lastId)) as Array<{ id: number; event: string; data: string }>;

    for (const row of rows) {
      lastId = row.id;
      // `data` is already a JSON string — forward verbatim in the SSE frame.
      res.write(`event: ${row.event}\ndata: ${row.data}\n\n`);
      if (TERMINAL.has(row.event)) {
        res.end();
        return;
      }
    }

    if (rows.length === 0) {
      await new Promise((r) => setTimeout(r, pollMs));
    }
  }

  // Timed out or client disconnected — close the response if still open.
  if (!res.writableEnded) {
    if (!clientGone && Date.now() >= deadline) {
      res.write(`event: error\ndata: ${JSON.stringify({ error: 'Analysis timed out' })}\n\n`);
    }
    res.end();
  }
}

/** Retention cleanup — drop event rows older than the given age (default 24h). */
export async function cleanupOldJobEvents(maxAgeMs = 24 * 60 * 60 * 1000): Promise<void> {
  const db = getDb();
  try {
    await db.prepare('DELETE FROM job_events WHERE created_at < ?').run(Date.now() - maxAgeMs);
  } catch (err) {
    logger.warn({ err }, 'job_events cleanup skipped');
  }
}
