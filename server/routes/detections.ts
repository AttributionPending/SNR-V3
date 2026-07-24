/**
 * Detection coverage — aggregate the detection rules produced across every
 * analysed incident and map them to ATT&CK.
 *
 *   GET /api/detections/coverage           — per-technique coverage + summary
 *   GET /api/detections/rules?technique=&type= — the rules behind a technique
 *   GET /api/detections/coverage/navigator — coverage as an ATT&CK Navigator layer
 *
 * Two independent signals are merged per technique, because they answer
 * different questions and their disagreement is the useful part:
 *   1. rule coverage   — rules we have written that map to the technique
 *                        (detection_rule_observations, built by
 *                        server/lib/detection-index.ts)
 *   2. analysis verdict — attack_chain[].detection_coverage, i.e. whether the
 *                        analysis believed existing controls would catch it
 *
 * Team-scoped and restricted to live (non-deleted, complete) sessions, matching
 * every other aggregate route.
 */
import { Router } from 'express';
import { getDb } from '../db/database.js';
import { coverageStatus } from '../lib/detection-index.js';
import { buildCoverageNavigatorLayer, type CoverageTechnique } from '../lib/stix.js';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';

const router = Router();

interface TechniqueRow {
  technique_id: string;
  technique_name: string;
  tactic: string | null;
  sessions: number;
  detected_votes: number;
  gap_votes: number;
  unknown_votes: number;
}
interface RuleAggRow {
  technique_id: string | null;
  rule_count: number;
  sigma: number;
  yara: number;
  suricata: number;
}

/** Observed techniques + verdict tallies, and rule counts per technique. */
async function loadCoverage(teamId: string): Promise<CoverageTechnique[]> {
  const db = getDb();
  const sTeam = teamId ? 'AND s.team_id = ?' : '';
  const sTeamP = teamId ? [teamId] : [];
  const dTeam = teamId ? 'WHERE d.team_id = ?' : '';
  const dTeamP = teamId ? [teamId] : [];
  const live = "s.deleted_at IS NULL AND s.status = 'complete'";

  const [techRows, ruleRows] = await Promise.all([
    db.prepare(`
      SELECT technique_id,
             MAX(technique_name) AS technique_name,
             MAX(tactic)         AS tactic,
             COUNT(DISTINCT session_id) AS sessions,
             COUNT(*) FILTER (WHERE coverage = 'Likely Detected') AS detected_votes,
             COUNT(*) FILTER (WHERE coverage = 'Detection Gap')   AS gap_votes,
             COUNT(*) FILTER (WHERE coverage NOT IN ('Likely Detected','Detection Gap') OR coverage IS NULL) AS unknown_votes
      FROM (
        SELECT UPPER(COALESCE(tech.value ->> 'sub_technique_id', tech.value ->> 'technique_id')) AS technique_id,
               COALESCE(tech.value ->> 'sub_technique_name', tech.value ->> 'technique_name')    AS technique_name,
               tech.value ->> 'tactic'             AS tactic,
               tech.value ->> 'detection_coverage' AS coverage,
               ar.session_id
        FROM analysis_results ar JOIN sessions s ON s.id = ar.session_id,
             snr_json_array(ar.result_json, 'attack_chain') AS tech(value)
        WHERE ${live} ${sTeam} AND tech.value ->> 'technique_id' IS NOT NULL
      ) t
      GROUP BY technique_id
    `).all(...sTeamP),

    db.prepare(`
      SELECT d.technique_id,
             COUNT(*) AS rule_count,
             COUNT(*) FILTER (WHERE d.rule_type = 'sigma')    AS sigma,
             COUNT(*) FILTER (WHERE d.rule_type = 'yara')     AS yara,
             COUNT(*) FILTER (WHERE d.rule_type = 'suricata') AS suricata
      FROM detection_rule_observations d
      ${dTeam}
      GROUP BY d.technique_id
    `).all(...dTeamP),
  ]);

  const byId = new Map<string, CoverageTechnique & { rules_by_type: Record<string, number> }>();

  for (const r of techRows as TechniqueRow[]) {
    if (!r.technique_id) continue;
    byId.set(r.technique_id, {
      technique_id: r.technique_id,
      technique_name: r.technique_name ?? 'Unknown',
      tactic: r.tactic ?? null,
      sessions: Number(r.sessions),
      rule_count: 0,
      detected_votes: Number(r.detected_votes),
      gap_votes: Number(r.gap_votes),
      status: 'unknown',
      rules_by_type: { sigma: 0, yara: 0, suricata: 0 },
    });
  }

  // A technique with rules but never observed is still real coverage — include it.
  for (const r of ruleRows as RuleAggRow[]) {
    if (!r.technique_id) continue;
    const existing = byId.get(r.technique_id) ?? {
      technique_id: r.technique_id,
      technique_name: r.technique_id,
      tactic: null,
      sessions: 0,
      rule_count: 0,
      detected_votes: 0,
      gap_votes: 0,
      status: 'unknown' as const,
      rules_by_type: { sigma: 0, yara: 0, suricata: 0 },
    };
    existing.rule_count = Number(r.rule_count);
    existing.rules_by_type = { sigma: Number(r.sigma), yara: Number(r.yara), suricata: Number(r.suricata) };
    byId.set(r.technique_id, existing);
  }

  for (const t of byId.values()) t.status = coverageStatus(t.rule_count, t.gap_votes, t.detected_votes);
  return [...byId.values()];
}

// ── GET /api/detections/coverage ──────────────────────────────────────────────
router.get('/coverage', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const teamId = authReq.teamId;
  const db = getDb();
  const techniques = await loadCoverage(teamId);

  const dTeam = teamId ? 'WHERE team_id = ?' : '';
  const dTeamP = teamId ? [teamId] : [];
  const totals = (await db.prepare(`
    SELECT COUNT(*) AS rules_total,
           COUNT(DISTINCT rule_hash) AS rules_distinct,
           COUNT(*) FILTER (WHERE technique_id IS NULL) AS unmapped_rules,
           COUNT(*) FILTER (WHERE rule_type = 'sigma')    AS sigma,
           COUNT(*) FILTER (WHERE rule_type = 'yara')     AS yara,
           COUNT(*) FILTER (WHERE rule_type = 'suricata') AS suricata
    FROM detection_rule_observations ${dTeam}
  `).get(...dTeamP)) as Record<string, number>;

  techniques.sort(
    (a, b) => b.gap_votes - a.gap_votes || b.sessions - a.sessions || a.technique_id.localeCompare(b.technique_id),
  );

  res.json({
    summary: {
      techniques_observed: techniques.filter((t) => t.sessions > 0).length,
      techniques_with_rules: techniques.filter((t) => t.rule_count > 0).length,
      techniques_gap: techniques.filter((t) => t.status === 'gap').length,
      techniques_partial: techniques.filter((t) => t.status === 'partial').length,
      rules_total: Number(totals?.rules_total ?? 0),
      rules_distinct: Number(totals?.rules_distinct ?? 0),
      unmapped_rules: Number(totals?.unmapped_rules ?? 0),
      rules_by_type: {
        sigma: Number(totals?.sigma ?? 0),
        yara: Number(totals?.yara ?? 0),
        suricata: Number(totals?.suricata ?? 0),
      },
    },
    techniques,
  });
});

// ── GET /api/detections/rules?technique=&type= ────────────────────────────────
router.get('/rules', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const teamId = authReq.teamId;
  const technique = ((req.query['technique'] as string) || '').trim().toUpperCase();
  const type = ((req.query['type'] as string) || '').trim().toLowerCase();
  const limit = Math.min(parseInt(req.query['limit'] as string) || 100, 500);

  const clauses: string[] = [];
  const params: unknown[] = [];
  if (teamId) { clauses.push('d.team_id = ?'); params.push(teamId); }
  if (technique === 'UNMAPPED') clauses.push('d.technique_id IS NULL');
  else if (technique) { clauses.push('d.technique_id = ?'); params.push(technique); }
  if (type) { clauses.push('d.rule_type = ?'); params.push(type); }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  params.push(limit);

  const rows = (await getDb().prepare(`
    SELECT d.id, d.rule_type, d.rule_name, d.rule_hash, d.rule_content, d.description, d.source,
           d.confidence, d.technique_id, d.created_at,
           d.session_id, s.name AS session_name
    FROM detection_rule_observations d
    JOIN sessions s ON s.id = d.session_id AND s.deleted_at IS NULL
    ${where}
    ORDER BY d.rule_type, d.rule_name
    LIMIT ?
  `).all(...params)) as Array<Record<string, unknown>>;

  res.json({ rules: rows });
});

// ── GET /api/detections/coverage/navigator ────────────────────────────────────
router.get('/coverage/navigator', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const techniques = await loadCoverage(authReq.teamId);
  const layer = buildCoverageNavigatorLayer(techniques);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="snr-detection-coverage.json"');
  res.send(JSON.stringify(layer, null, 2));
});

export default router;
