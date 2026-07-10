/**
 * Neighborhood link-analysis graph — GET /api/graph?seed=<seed>.
 * Seed forms: session:<id> | actor:<id> | ioc:<type>:<value>. Resolves the seed
 * to its set of team-scoped live sessions and builds the same graph the case
 * view uses, so an analyst can pivot from any actor or indicator.
 */
import { Router } from 'express';
import { getDb } from '../db/database.js';
import { resolveSeedSessions, buildGraphForSessions } from '../lib/graph-db.js';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';

const router = Router();

router.get('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const seed = ((req.query['seed'] as string) || '').trim();
  if (!seed || !/^(session|actor|ioc):/.test(seed)) {
    res.status(400).json({ error: 'seed must be session:<id>, actor:<id>, or ioc:<type>:<value>' });
    return;
  }
  const db = getDb();
  const sessionIds = await resolveSeedSessions(db, authReq.teamId, seed);
  const graph = await buildGraphForSessions(db, sessionIds);
  res.json(graph);
});

export default router;
