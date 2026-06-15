import { DatabaseSync } from 'node:sqlite';

const db = new DatabaseSync('./snr.db');

const rows = db.prepare("SELECT ar.session_id, json_extract(ar.result_json, '$.threat_actor.name') as actor_name FROM analysis_results ar WHERE json_extract(ar.result_json, '$.threat_actor.name') IS NOT NULL ORDER BY ar.created_at DESC").all();
console.log('Sessions with threat actors:');
for (const r of rows) {
  console.log(`  ${r.session_id} -> ${r.actor_name}`);
}

const links = db.prepare('SELECT * FROM session_threat_actors').all();
console.log(`\nLinks: ${links.length}`);

const actors = db.prepare('SELECT id, name FROM threat_actors').all();
console.log(`Actors: ${actors.length}`);
for (const a of actors) {
  console.log(`  ${a.id} -> ${a.name}`);
}

db.close();
