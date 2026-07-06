/**
 * One-time generator: fetch MITRE ATT&CK Enterprise STIX and emit a compact
 * technique list for the Analyst Workbench technique picker.
 *
 *   node scripts/gen-attack-techniques.mjs
 *
 * Writes src/data/attack-techniques.json — an array of { id, name, tactic }
 * (sub-techniques included), sorted by id. Re-run to refresh from upstream.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';
const OUT = fileURLToPath(new URL('../src/data/attack-techniques.json', import.meta.url));

const TACTIC_NAMES = {
  'reconnaissance': 'Reconnaissance', 'resource-development': 'Resource Development',
  'initial-access': 'Initial Access', 'execution': 'Execution', 'persistence': 'Persistence',
  'privilege-escalation': 'Privilege Escalation', 'defense-evasion': 'Defense Evasion',
  'credential-access': 'Credential Access', 'discovery': 'Discovery', 'lateral-movement': 'Lateral Movement',
  'collection': 'Collection', 'command-and-control': 'Command and Control', 'exfiltration': 'Exfiltration',
  'impact': 'Impact',
};

console.error('Fetching', SRC_URL, '…');
const res = await fetch(SRC_URL);
if (!res.ok) { console.error('Fetch failed', res.status); process.exit(1); }
const bundle = await res.json();

const out = [];
for (const o of bundle.objects) {
  if (o.type !== 'attack-pattern' || o.revoked || o.x_mitre_deprecated) continue;
  const ref = (o.external_references || []).find((r) => r.source_name === 'mitre-attack' && /^T\d{4}(\.\d{3})?$/.test(r.external_id || ''));
  if (!ref) continue;
  const tactic = TACTIC_NAMES[(o.kill_chain_phases || []).find((p) => p.kill_chain_name === 'mitre-attack')?.phase_name] || '';
  out.push({ id: ref.external_id, name: o.name, tactic });
}
out.sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify(out));
console.error(`Wrote ${out.length} techniques -> ${OUT}`);
