#!/usr/bin/env tsx
/**
 * One-off (idempotent) maintenance: canonicalize defanged network IOCs already
 * stored before the refang-at-ingestion fix. Re-runs the current
 * validateAndDeduplicateIOCs over every stored analysis_results.iocs array
 * (which now refangs evil[.]com → evil.com, clears stale "invalid" flags, and
 * re-dedups defanged/fanged pairs) and refreshes the ioc_observations display
 * values to match. Safe to run repeatedly — refang and validation are stable.
 *
 * Usage: npx tsx scripts/backfill-refang-iocs.ts   (requires DATABASE_URL)
 *        add --dry to report changes without writing.
 */
import path from 'path';
import { fileURLToPath } from 'url';
import { config } from 'dotenv';
import { rawQuery, closeDb } from '../server/db/client.js';
import { validateAndDeduplicateIOCs } from '../server/lib/ioc-validator.js';
import { refang } from '../server/lib/defang.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
config({ path: path.resolve(__dirname, '../.env') });

const DRY = process.argv.includes('--dry');

async function main() {
  // 1. Rewrite stored analysis results (all versions).
  const results = await rawQuery('SELECT id, result_json FROM analysis_results');
  let resultsChanged = 0;
  let iocsCanonicalized = 0;

  for (const row of results.rows as Array<{ id: string; result_json: string }>) {
    let result: { iocs?: Array<{ type?: unknown; value?: unknown }> };
    try { result = JSON.parse(row.result_json); } catch { continue; }
    if (!Array.isArray(result.iocs) || result.iocs.length === 0) continue;

    // Only feed well-formed IOCs to the validator (older data may hold nulls);
    // malformed entries are preserved untouched.
    const wellFormed = (i: { type?: unknown; value?: unknown }) =>
      i && typeof i.type === 'string' && typeof i.value === 'string' && i.value.trim().length > 0;
    const good = result.iocs.filter(wellFormed) as Array<{ type: string; value: string }>;
    const bad = result.iocs.filter((i) => !wellFormed(i));
    if (good.length === 0) continue;

    const before = JSON.stringify(good);
    const willChange = good.filter((i) => refang(i.value, i.type) !== i.value).length;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const processed = validateAndDeduplicateIOCs(good as any);
    const after = JSON.stringify(processed);

    if (before !== after) {
      resultsChanged++;
      iocsCanonicalized += willChange;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      result.iocs = [...processed, ...bad] as any;
      if (!DRY) await rawQuery('UPDATE analysis_results SET result_json = $1 WHERE id = $2', [JSON.stringify(result), row.id]);
    }
  }

  // 2. Refresh the ioc_observations display column (the norm key already refangs).
  const obs = await rawQuery('SELECT id, ioc_type, ioc_value FROM ioc_observations');
  let obsChanged = 0;
  for (const o of obs.rows as Array<{ id: string; ioc_type: string; ioc_value: string }>) {
    const rf = refang(o.ioc_value, o.ioc_type);
    if (rf !== o.ioc_value) {
      obsChanged++;
      if (!DRY) await rawQuery('UPDATE ioc_observations SET ioc_value = $1 WHERE id = $2', [rf, o.id]);
    }
  }

  console.log(`${DRY ? '[DRY RUN] ' : ''}analysis_results scanned: ${results.rows.length}`);
  console.log(`${DRY ? '[DRY RUN] ' : ''}results rewritten: ${resultsChanged} (network IOCs canonicalized: ${iocsCanonicalized})`);
  console.log(`${DRY ? '[DRY RUN] ' : ''}ioc_observations display values refanged: ${obsChanged}`);

  await closeDb();
}

main().catch(async (err) => {
  console.error('backfill-refang-iocs failed:', err instanceof Error ? err.message : err);
  await closeDb().catch(() => {});
  process.exit(1);
});
