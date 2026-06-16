/**
 * Integration API (v1) — machine-authenticated endpoints for programmatic use.
 *
 * Mounted behind requireApiKey (see index.ts), so req.user/req.teamId/req.scopes
 * are populated from the service account. All access is team-scoped. Submitting an
 * analysis enqueues the same background job the UI uses and returns a job id;
 * results are fetched by polling, or pushed via an optional completion webhook.
 */
import { Router } from 'express';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import type { Request, Response } from 'express';
import { getDb, loadMergedSettings, appendAuditLog } from '../db/database.js';
import { enqueueAnalysis } from '../jobs/queue.js';
import { buildStixBundle, buildNavigatorLayer } from '../lib/stix.js';
import { requireScope, type ServiceAuthRequest } from '../middleware/apiKey.js';
import type { AnalysisResult } from '../lib/claude.js';
import logger from '../lib/logger.js';

const router = Router();

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Fetch a team-scoped session or send 404. */
async function fetchSession(req: Request, res: Response): Promise<Record<string, unknown> | null> {
  const sreq = req as ServiceAuthRequest;
  const db = getDb();
  const session = (await db
    .prepare('SELECT * FROM sessions WHERE id = ? AND team_id = ? AND deleted_at IS NULL')
    .get(req.params.id, sreq.teamId)) as Record<string, unknown> | undefined;
  if (!session) {
    res.status(404).json({ error: 'Analysis not found' });
    return null;
  }
  return session;
}

/** Load the latest result for a session, with analyst false-positive IOCs removed. */
async function loadResult(sessionId: string): Promise<AnalysisResult | null> {
  const db = getDb();
  const row = (await db
    .prepare(
      'SELECT result_json, analyst_overrides FROM analysis_results WHERE session_id = ? ORDER BY version DESC LIMIT 1'
    )
    .get(sessionId)) as { result_json: string; analyst_overrides?: string } | undefined;
  if (!row) return null;
  const result = JSON.parse(row.result_json) as AnalysisResult;
  try {
    const overrides = row.analyst_overrides ? JSON.parse(row.analyst_overrides) : {};
    const fps: string[] = overrides.ioc_false_positives ?? [];
    if (Array.isArray(fps) && fps.length > 0 && Array.isArray(result.iocs)) {
      const fpSet = new Set(fps);
      result.iocs = result.iocs.filter((i) => !fpSet.has(`${i.type}::${i.value}`));
    }
  } catch { /* ignore */ }
  return result;
}

// POST /api/v1/analyze — submit a new analysis (returns a job id).
router.post('/analyze', requireScope('analyze:write'), async (req: Request, res: Response) => {
  const sreq = req as ServiceAuthRequest;
  const { name, audience, siem, text, redacted_strings, webhook_url } = (req.body ?? {}) as {
    name?: string;
    audience?: string;
    siem?: string;
    text?: string;
    redacted_strings?: string[];
    webhook_url?: string;
  };

  if (!audience) {
    res.status(400).json({ error: 'audience is required' });
    return;
  }
  if (!siem && !text) {
    res.status(400).json({ error: 'At least one of siem or text is required' });
    return;
  }
  if (webhook_url && !/^https?:\/\//i.test(webhook_url)) {
    res.status(400).json({ error: 'webhook_url must be an http(s) URL' });
    return;
  }

  let siemClean = siem ?? '';
  let textClean = text ?? '';
  if (Array.isArray(redacted_strings)) {
    for (const p of redacted_strings) {
      if (typeof p !== 'string' || !p) continue;
      const re = new RegExp(escapeRegex(p), 'gi');
      siemClean = siemClean.replace(re, '[REDACTED]');
      textClean = textClean.replace(re, '[REDACTED]');
    }
  }

  const db = getDb();
  const sessionId = uuidv4();
  const now = Date.now();
  const inputHash = crypto.createHash('sha256').update([siemClean, textClean].join('||')).digest('hex');

  // created_by is null — service accounts are not users.
  await db
    .prepare(
      `INSERT INTO sessions (id, name, created_at, updated_at, audience, status, team_id, created_by, input_hash)
       VALUES (?, ?, ?, ?, ?, 'analyzing', ?, NULL, ?)`
    )
    .run(sessionId, name?.trim() || `API analysis ${new Date(now).toISOString().slice(0, 10)}`, now, now, audience, sreq.teamId, inputHash);

  if (siemClean) {
    await db.prepare('INSERT INTO session_inputs (id, session_id, input_type, content, created_at) VALUES (?,?,?,?,?)')
      .run(uuidv4(), sessionId, 'siem', siemClean, now);
  }
  if (textClean) {
    await db.prepare('INSERT INTO session_inputs (id, session_id, input_type, content, created_at) VALUES (?,?,?,?,?)')
      .run(uuidv4(), sessionId, 'text', textClean, now);
  }

  const jobId = await enqueueAnalysis({
    sessionId,
    siemClean,
    textClean,
    logClean: '',
    audience,
    inputHash,
    auditAction: 'analysis_complete',
    teamId: sreq.teamId,
    userId: null,
    displayName: sreq.user.displayName,
    webhookUrl: webhook_url ?? null,
  });

  appendAuditLog({
    analyst_name: sreq.user.displayName,
    session_id: sessionId,
    action: 'api_analysis_submitted',
    input_hash: inputHash,
    details: `via API key ${sreq.apiKeyId}, audience=${audience}`,
  });

  logger.info({ sessionId, jobId, account: sreq.user.displayName }, 'API analysis submitted');
  res.status(202).json({ sessionId, jobId, status: 'queued' });
});

// GET /api/v1/analyses/:id — poll status.
router.get('/analyses/:id', requireScope('sessions:read'), async (req: Request, res: Response) => {
  const session = await fetchSession(req, res);
  if (!session) return;
  res.json({
    sessionId: session.id,
    name: session.name,
    status: session.status,
    severity: session.severity ?? null,
    audience: session.audience ?? null,
    version: session.version ?? null,
    createdAt: session.created_at,
    updatedAt: session.updated_at,
  });
});

// GET /api/v1/analyses/:id/result — fetch the structured result.
router.get('/analyses/:id/result', requireScope('sessions:read'), async (req: Request, res: Response) => {
  const session = await fetchSession(req, res);
  if (!session) return;
  const result = await loadResult(req.params.id);
  if (!result) {
    res.status(409).json({ error: 'Analysis not complete', status: session.status });
    return;
  }
  res.json({ sessionId: session.id, status: session.status, result });
});

// GET /api/v1/analyses/:id/export/:format — stix | navigator | iocs
router.get('/analyses/:id/export/:format', requireScope('export:read'), async (req: Request, res: Response) => {
  const sreq = req as ServiceAuthRequest;
  const session = await fetchSession(req, res);
  if (!session) return;
  const result = await loadResult(req.params.id);
  if (!result) {
    res.status(409).json({ error: 'Analysis not complete', status: session.status });
    return;
  }
  const settings = await loadMergedSettings(sreq.teamId);
  const format = req.params.format;

  appendAuditLog({
    analyst_name: sreq.user.displayName,
    session_id: req.params.id,
    action: `export_${format}`,
    details: `via API key ${sreq.apiKeyId}`,
  });

  switch (format) {
    case 'stix': {
      const tlp = (settings.default_tlp || 'AMBER') as 'AMBER';
      const bundle = buildStixBundle(
        result,
        req.params.id,
        tlp,
        settings.analyst_name || 'CTI Analyst',
        settings.org_name || 'Security Operations',
      );
      res.json(bundle);
      return;
    }
    case 'navigator': {
      const layer = buildNavigatorLayer(result, String(session.name ?? 'Incident'));
      res.json(layer);
      return;
    }
    case 'iocs': {
      const iocs = (result.iocs ?? []).map((i) => ({ type: i.type, value: i.value, confidence: i.confidence, context: i.context }));
      res.json({ iocs });
      return;
    }
    default:
      res.status(400).json({ error: 'Unsupported format. Use: stix, navigator, iocs' });
  }
});

export default router;
