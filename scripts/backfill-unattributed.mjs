/**
 * One-time backfill: link completed sessions that have no threat actor
 * attribution to the team-scoped "Unattributed" placeholder.
 *
 * Safe to run multiple times — uses INSERT OR IGNORE on links.
 */
import { DatabaseSync } from 'node:sqlite';
import crypto from 'crypto';

const db = new DatabaseSync('./snr.db');
db.exec('PRAGMA foreign_keys = ON');

// Find completed sessions with no existing link
const unlinked = db.prepare(`
  SELECT s.id, s.team_id, s.created_by
  FROM sessions s
  WHERE s.status = 'complete'
    AND s.id NOT IN (SELECT session_id FROM session_threat_actors)
  ORDER BY s.created_at ASC
`).all();

if (unlinked.length === 0) {
  console.log('No unlinked sessions found — nothing to do.');
  db.close();
  process.exit(0);
}

console.log(`Found ${unlinked.length} unlinked session(s).`);

let linked = 0;
const now = Date.now();

// Group by team to find-or-create the Unattributed placeholder per team
const byTeam = new Map();
for (const row of unlinked) {
  if (!byTeam.has(row.team_id)) byTeam.set(row.team_id, []);
  byTeam.get(row.team_id).push(row);
}

for (const [teamId, sessions] of byTeam) {
  // Find or create the "Unattributed" placeholder for this team
  let placeholder = db.prepare(
    "SELECT id FROM threat_actors WHERE name = 'Unattributed' AND team_id = ?"
  ).get(teamId);

  if (!placeholder) {
    const id = crypto.randomUUID();
    db.prepare(`
      INSERT INTO threat_actors (id, name, aliases, motivation, attribution_confidence, intrusion_set, campaign_name, malware_families, description, team_id, created_by, created_at, updated_at)
      VALUES (?, 'Unattributed', '[]', NULL, NULL, NULL, NULL, '[]', 'Sessions where no specific threat actor could be attributed.', ?, ?, ?, ?)
    `).run(id, teamId, sessions[0].created_by, now, now);
    placeholder = { id };
    console.log(`  Created "Unattributed" placeholder for team ${teamId}`);
  }

  for (const session of sessions) {
    db.prepare(
      'INSERT OR IGNORE INTO session_threat_actors (session_id, threat_actor_id, link_type, linked_at, linked_by) VALUES (?, ?, ?, ?, ?)'
    ).run(session.id, placeholder.id, 'auto', now, session.created_by);
    linked++;
    console.log(`  Linked session ${session.id}`);
  }
}

console.log(`\nBackfill complete: ${linked} session(s) linked to Unattributed.`);
db.close();
