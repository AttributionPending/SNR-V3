/**
 * Threat-intel feed ingestion orchestrator.
 *
 * Resolves the right connector per feed type, deduplicates items, and turns each
 * new item into an analyzed session by enqueueing the Phase 2 analysis job. The
 * scheduler (scheduler.ts) calls pollDueFeeds() on an interval.
 */
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { getDb, appendAuditLog } from '../../db/database.js';
import { enqueueAnalysis } from '../../jobs/queue.js';
import { feedPollsTotal, feedItemsIngestedTotal } from '../metrics.js';
import logger from '../logger.js';
import { rssConnector } from './rss.js';
import { taxiiConnector } from './taxii.js';
import { mispConnector } from './misp.js';
import type { FeedConnector, FeedItem, FeedRow } from './types.js';

const CONNECTORS: Record<FeedRow['type'], FeedConnector> = {
  rss: rssConnector,
  taxii: taxiiConnector,
  misp: mispConnector,
};

export interface PollResult {
  fetched: number;
  ingested: number;
  skipped: number;
}

/** Fetch a feed's items (no DB writes) — used by the "test" endpoint. */
export async function testFeed(feed: FeedRow): Promise<{ count: number; sample: string[] }> {
  const items = await CONNECTORS[feed.type].fetchItems(feed);
  return { count: items.length, sample: items.slice(0, 5).map((i) => i.title) };
}

/** Ingest one item: dedupe, create a session, enqueue analysis. Returns true if new. */
async function ingestItem(feed: FeedRow, item: FeedItem): Promise<boolean> {
  const db = getDb();
  const contentHash = crypto.createHash('sha256').update(item.content).digest('hex');
  const itemRowId = uuidv4();
  const now = Date.now();

  // Atomic dedupe: only the first insert for (feed_id, source_id) wins.
  const inserted = await db
    .prepare(
      `INSERT INTO feed_items (id, feed_id, source_id, content_hash, created_at)
       VALUES (?, ?, ?, ?, ?) ON CONFLICT (feed_id, source_id) DO NOTHING`
    )
    .run(itemRowId, feed.id, item.sourceId, contentHash, now);
  if (inserted.changes === 0) return false; // already ingested

  // Create a session for this item and enqueue analysis (created_by null — feeds
  // are not users). Tags from the feed are applied to the session.
  const sessionId = uuidv4();
  const inputHash = crypto.createHash('sha256').update(item.content).digest('hex');
  const name = `[${feed.name}] ${item.title}`.slice(0, 200);
  await db
    .prepare(
      `INSERT INTO sessions (id, name, created_at, updated_at, audience, status, team_id, created_by, tags, input_hash)
       VALUES (?, ?, ?, ?, ?, 'analyzing', ?, NULL, ?, ?)`
    )
    .run(sessionId, name, now, now, feed.audience, feed.team_id, feed.tags || '[]', inputHash);
  await db
    .prepare('INSERT INTO session_inputs (id, session_id, input_type, content, created_at) VALUES (?,?,?,?,?)')
    .run(uuidv4(), sessionId, 'text', item.content, now);
  await db.prepare('UPDATE feed_items SET session_id = ? WHERE id = ?').run(sessionId, itemRowId);

  await enqueueAnalysis({
    sessionId,
    siemClean: '',
    textClean: item.content,
    logClean: '',
    audience: feed.audience,
    inputHash,
    auditAction: 'analysis_complete',
    teamId: feed.team_id,
    userId: null,
    displayName: `feed:${feed.name}`,
  });
  return true;
}

/** Poll a single feed and ingest up to max_items new items. */
export async function pollFeed(feed: FeedRow): Promise<PollResult> {
  const result: PollResult = { fetched: 0, ingested: 0, skipped: 0 };
  const items = await CONNECTORS[feed.type].fetchItems(feed);
  result.fetched = items.length;

  // Newest first when timestamps exist, then cap per poll to bound analysis cost.
  items.sort((a, b) => (b.publishedAt ?? 0) - (a.publishedAt ?? 0));
  for (const item of items.slice(0, feed.max_items)) {
    try {
      if (await ingestItem(feed, item)) result.ingested++;
      else result.skipped++;
    } catch (err) {
      logger.warn({ err, feedId: feed.id, sourceId: item.sourceId }, 'Feed item ingest failed');
    }
  }
  if (result.ingested > 0) feedItemsIngestedTotal.inc({ type: feed.type }, result.ingested);
  return result;
}

/**
 * Poll all enabled feeds that are due. Each feed is claimed atomically (sets
 * last_polled_at) before polling so concurrent schedulers don't double-poll.
 */
export async function pollDueFeeds(): Promise<void> {
  const db = getDb();
  const now = Date.now();
  const due = (await db
    .prepare(
      `SELECT * FROM feeds WHERE enabled = 1
       AND (last_polled_at IS NULL OR last_polled_at <= ? - (cadence_minutes::bigint * 60000))`
    )
    .all(now)) as FeedRow[];

  for (const feed of due) {
    // Claim: re-check due condition in the UPDATE to avoid races.
    const claim = await db
      .prepare(
        `UPDATE feeds SET last_polled_at = ? WHERE id = ?
         AND (last_polled_at IS NULL OR last_polled_at <= ? - (cadence_minutes::bigint * 60000))`
      )
      .run(now, feed.id, now);
    if (claim.changes === 0) continue; // another scheduler claimed it

    try {
      const r = await pollFeed(feed);
      const status = `ok: ${r.ingested} new, ${r.skipped} dup, ${r.fetched} fetched @ ${new Date(now).toISOString()}`;
      await db.prepare('UPDATE feeds SET last_status = ? WHERE id = ?').run(status, feed.id);
      feedPollsTotal.inc({ type: feed.type, result: 'success' });
      if (r.ingested > 0) {
        appendAuditLog({
          analyst_name: `feed:${feed.name}`,
          action: 'feed_ingested',
          details: `${r.ingested} new item(s) from "${feed.name}" (${feed.type})`,
        });
      }
      logger.info({ feedId: feed.id, ...r }, `Feed "${feed.name}" polled`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'poll failed';
      await db.prepare('UPDATE feeds SET last_status = ? WHERE id = ?').run(`error: ${msg}`, feed.id);
      feedPollsTotal.inc({ type: feed.type, result: 'failed' });
      logger.warn({ err, feedId: feed.id }, 'Feed poll failed');
    }
  }
}
