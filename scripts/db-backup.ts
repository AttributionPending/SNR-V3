#!/usr/bin/env tsx
/**
 * SNR Database Backup Script
 * Usage: npm run db:backup
 * Creates a timestamped copy of snr.db in the backups/ directory.
 */

import fs from 'fs';
import path from 'path';
import { config } from 'dotenv';

const __dirname = path.dirname(new URL(import.meta.url).pathname);
config({ path: path.resolve(__dirname, '../.env') });

const dbPath = path.resolve(process.env.DB_PATH ?? './snr.db');
const backupDir = path.resolve(__dirname, '../backups');

if (!fs.existsSync(dbPath)) {
  console.error(`✗ Database not found at ${dbPath}`);
  process.exit(1);
}

// Create backup directory
if (!fs.existsSync(backupDir)) {
  fs.mkdirSync(backupDir, { recursive: true });
}

const timestamp = new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
const backupFilename = `snr-${timestamp}.db`;
const backupPath = path.join(backupDir, backupFilename);

// Copy main database file
fs.copyFileSync(dbPath, backupPath);

// Copy WAL file if it exists
const walPath = dbPath + '-wal';
if (fs.existsSync(walPath)) {
  fs.copyFileSync(walPath, backupPath + '-wal');
}

// Copy SHM file if it exists
const shmPath = dbPath + '-shm';
if (fs.existsSync(shmPath)) {
  fs.copyFileSync(shmPath, backupPath + '-shm');
}

const size = (fs.statSync(backupPath).size / 1024).toFixed(1);
console.log(`✓ Backup created: ${backupPath} (${size} KB)`);

// List existing backups
const backups = fs.readdirSync(backupDir)
  .filter(f => f.startsWith('snr-') && f.endsWith('.db'))
  .sort()
  .reverse();

console.log(`  ${backups.length} backup(s) in ${backupDir}`);

// Warn if more than 10 backups
if (backups.length > 10) {
  console.log(`  ⚠ Consider cleaning up old backups (${backups.length} total)`);
}
