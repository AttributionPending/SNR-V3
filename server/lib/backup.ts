/**
 * Scheduled database backups for on-prem operation.
 *
 * Uses SQLite `VACUUM INTO` to produce a consistent point-in-time snapshot
 * (safe even with WAL active, unlike a raw file copy). Snapshots are written to
 * a backups directory and pruned to the most recent N. Restore is a manual op:
 * stop the server, replace $DB_PATH with a snapshot, start again.
 */
import fs from 'fs';
import path from 'path';
import { getDb } from '../db/database.js';
import logger from './logger.js';

function backupDir(): string {
  if (process.env.BACKUP_DIR) return path.resolve(process.env.BACKUP_DIR);
  // Default: a "backups" folder next to the database file
  const dbPath = path.resolve(process.env.DB_PATH || './snr.db');
  return path.join(path.dirname(dbPath), 'backups');
}

/** Take a single consistent snapshot. Returns the snapshot path, or null on failure. */
export function runBackup(): string | null {
  try {
    const dir = backupDir();
    fs.mkdirSync(dir, { recursive: true });
    const ts = new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
    const dest = path.join(dir, `snr-${ts}.db`);
    const db = getDb();
    // VACUUM INTO writes a fully consistent copy; single-quote-escape the path.
    db.exec(`VACUUM INTO '${dest.replace(/'/g, "''")}'`);
    pruneOldBackups(dir);
    const sizeKb = (fs.statSync(dest).size / 1024).toFixed(1);
    logger.info({ dest, sizeKb }, 'Database backup created');
    return dest;
  } catch (err) {
    logger.error({ err }, 'Database backup failed');
    return null;
  }
}

/** Keep only the newest BACKUP_RETENTION (default 7) snapshots. */
function pruneOldBackups(dir: string): void {
  const retention = parseInt(process.env.BACKUP_RETENTION ?? '7', 10) || 7;
  const snaps = fs.readdirSync(dir)
    .filter((f) => /^snr-.*\.db$/.test(f))
    .sort()
    .reverse();
  for (const stale of snaps.slice(retention)) {
    try { fs.unlinkSync(path.join(dir, stale)); } catch { /* best effort */ }
  }
}

/**
 * Start the periodic backup scheduler. Returns a stop() function (for graceful
 * shutdown). BACKUP_INTERVAL_HOURS=0 disables scheduling entirely.
 */
export function startBackupScheduler(): () => void {
  const hours = parseInt(process.env.BACKUP_INTERVAL_HOURS ?? '24', 10);
  if (!hours || hours <= 0) {
    logger.info('Scheduled backups disabled (BACKUP_INTERVAL_HOURS=0)');
    return () => {};
  }
  logger.info({ intervalHours: hours, dir: backupDir() }, 'Scheduled database backups enabled');
  const timer = setInterval(() => runBackup(), hours * 60 * 60 * 1000);
  timer.unref?.();
  return () => clearInterval(timer);
}
