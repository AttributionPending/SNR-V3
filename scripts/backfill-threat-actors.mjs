/**
 * One-time backfill: scan all existing analysis results and auto-link
 * sessions that have threat_actor.name to canonical threat actor records.
 *
 * Safe to run multiple times — uses INSERT OR IGNORE on links.
 */
import { DatabaseSync } from 'node:sqlite';
import crypto from 'crypto';

const db = new DatabaseSync('./snr.db');
db.exec('PRAGMA foreign_keys = ON');

const rows = db.prepare(`
  SELECT ar.session_id, ar.result_json, s.team_id, s.created_by
  FROM analysis_results ar
  JOIN sessions s ON s.id = ar.session_id
  WHERE json_extract(ar.result_json, '$.threat_actor.name') IS NOT NULL
  ORDER BY ar.created_at ASC
`).all();

let created = 0;
let linked = 0;

for (const row of rows) {
  const result = JSON.parse(row.result_json);
  const actor = result.threat_actor;
  if (!actor?.name?.trim()) continue;

  const name = actor.name.trim();
  const nameLower = name.toLowerCase();
  const teamId = row.team_id;
  const userId = row.created_by;
  const now = Date.now();

  // Check if already linked
  const existing = db.prepare('SELECT threat_actor_id FROM session_threat_actors WHERE session_id = ?').get(row.session_id);
  if (existing) continue;

  // Find or create canonical actor
  let matched = db.prepare('SELECT * FROM threat_actors WHERE LOWER(name) = ? AND team_id = ?').get(nameLower, teamId);

  if (!matched) {
    // Check aliases
    const allActors = db.prepare('SELECT * FROM threat_actors WHERE team_id = ?').all(teamId);
    for (const a of allActors) {
      try {
        const aliases = JSON.parse(a.aliases || '[]');
        if (aliases.some(alias => alias.toLowerCase() === nameLower)) {
          matched = a;
          break;
        }
      } catch {}
    }
  }

  if (!matched) {
    const actorId = crypto.randomUUID();
    db.prepare(`
      INSERT INTO threat_actors (id, name, aliases, motivation, attribution_confidence, intrusion_set, campaign_name, malware_families, description, team_id, created_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      actorId, name, JSON.stringify(actor.aliases || []),
      actor.motivation || null, actor.attribution_confidence || null,
      actor.intrusion_set || null, actor.campaign_name || null,
      JSON.stringify(actor.malware_families || []), '',
      teamId, userId, now, now
    );
    matched = { id: actorId };
    created++;
    console.log(`  Created actor: ${name}`);
  }

  db.prepare('INSERT OR IGNORE INTO session_threat_actors (session_id, threat_actor_id, link_type, linked_at, linked_by) VALUES (?, ?, ?, ?, ?)')
    .run(row.session_id, matched.id, 'auto', now, userId);
  linked++;
  console.log(`  Linked session ${row.session_id} -> ${name}`);
}

console.log(`\nBackfill complete: ${created} actors created, ${linked} sessions linked`);
db.close();
