#!/usr/bin/env tsx
/**
 * SNR Database Restore Script
 * Usage: npm run db:restore -- <backup-file>
 * Restores snr.db from a backup file. Creates a safety backup of current DB first.
 */

import fs from 'fs';
import path from 'path';
import { config } from 'dotenv';

const __dirname = path.dirname(new URL(import.meta.url).pathname);
config({ path: path.resolve(__dirname, '../.env') });

const dbPath = path.resolve(process.env.DB_PATH ?? './snr.db');
const backupDir = path.resolve(__dirname, '../backups');

const restoreFile = process.argv[2];

if (!restoreFile) {
  console.error('Usage: npm run db:restore -- <backup-file>');
  console.error('');

  // List available backups
  if (fs.existsSync(backupDir)) {
    const backups = fs.readdirSync(backupDir)
      .filter(f => f.startsWith('snr-') && f.endsWith('.db'))
      .sort()
      .reverse();

    if (backups.length > 0) {
      console.error('Available backups:');
      for (const b of backups) {
        const stat = fs.statSync(path.join(backupDir, b));
        const size = (stat.size / 1024).toFixed(1);
        console.error(`  ${b}  (${size} KB)`);
      }
    } else {
      console.error('No backups found.');
    }
  }
  process.exit(1);
}

// Resolve backup path (try as-is, then in backups dir)
let sourcePath = path.resolve(restoreFile);
if (!fs.existsSync(sourcePath)) {
  sourcePath = path.join(backupDir, restoreFile);
}
if (!fs.existsSync(sourcePath)) {
  console.error(`✗ Backup file not found: ${restoreFile}`);
  process.exit(1);
}

// Safety backup of current DB
if (fs.existsSync(dbPath)) {
  const safetyPath = dbPath + '.pre-restore';
  fs.copyFileSync(dbPath, safetyPath);
  console.log(`✓ Safety backup of current DB: ${safetyPath}`);
}

// Remove WAL/SHM from current DB
for (const ext of ['-wal', '-shm']) {
  const p = dbPath + ext;
  if (fs.existsSync(p)) fs.unlinkSync(p);
}

// Restore
fs.copyFileSync(sourcePath, dbPath);

// Copy WAL if it exists in backup
const sourceWal = sourcePath + '-wal';
if (fs.existsSync(sourceWal)) {
  fs.copyFileSync(sourceWal, dbPath + '-wal');
}

const size = (fs.statSync(dbPath).size / 1024).toFixed(1);
console.log(`✓ Database restored from ${path.basename(sourcePath)} (${size} KB)`);
console.log('  Restart the server to apply changes.');
