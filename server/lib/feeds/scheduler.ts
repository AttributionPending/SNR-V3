/**
 * Periodic feed poller. Runs in the API process: every FEED_POLL_INTERVAL_SECONDS
 * it polls any enabled feed whose cadence has elapsed. Per-feed claiming (see
 * pollDueFeeds) keeps this safe if more than one instance runs.
 */
import { pollDueFeeds } from './index.js';
import logger from '../logger.js';

export function startFeedScheduler(): () => void {
  const intervalSec = parseInt(process.env.FEED_POLL_INTERVAL_SECONDS ?? '60', 10);
  if (!intervalSec || intervalSec <= 0) {
    logger.info('Feed scheduler disabled (FEED_POLL_INTERVAL_SECONDS=0)');
    return () => {};
  }

  let running = false;
  const tick = async () => {
    if (running) return; // don't overlap polls
    running = true;
    try {
      await pollDueFeeds();
    } catch (err) {
      logger.error({ err }, 'Feed scheduler tick failed');
    } finally {
      running = false;
    }
  };

  logger.info({ intervalSec }, 'Feed scheduler enabled');
  const timer = setInterval(() => void tick(), intervalSec * 1000);
  timer.unref?.();
  // Kick once shortly after startup so feeds don't wait a full interval.
  setTimeout(() => void tick(), 5000).unref?.();
  return () => clearInterval(timer);
}
