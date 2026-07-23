/**
 * Indicator enrichment.
 *
 *   GET  /api/enrichment?type=&value=      — run the team's enabled providers
 *   GET  /api/enrichment/catalog           — built-in presets for the admin UI
 *   GET  /api/enrichment/providers         — list (never returns api_key)
 *   POST /api/enrichment/providers         — add a catalog preset or custom provider
 *   PATCH/DELETE /api/enrichment/providers/:id
 *   POST /api/enrichment/providers/:id/test — one-shot lookup against a sample
 *
 * Provider management mirrors server/routes/feeds.ts: per-team, admin-or-lead
 * gated, and the stored secret never leaves the server (list returns `has_key`).
 * The lookup endpoint itself is open to any team member.
 */
import { Router } from 'express';
import crypto from 'crypto';
import { getDb, loadMergedSettings } from '../db/database.js';
import { normalizeIocValue } from '../lib/ioc-index.js';
import { enrichIndicator, providersFor, loadProviders, invalidateProviderCache } from '../lib/enrichment/index.js';
import { CATALOG, catalogEntry } from '../lib/enrichment/catalog.js';
import { providerFromRow, parseConfig } from '../lib/enrichment/http-provider.js';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';

const router = Router();

/** Masked placeholder the client echoes back for an unchanged key. */
const MASKED = '••••••••';

/** Admin or team lead, matching the feeds router's rule. */
async function requireAdminOrLead(req: Request, res: Response): Promise<boolean> {
  const authReq = req as AuthenticatedRequest;
  if (!authReq.teamId) { res.status(400).json({ error: 'X-Team-Id header required' }); return false; }
  if (authReq.user.role === 'admin') return true;
  const m = (await getDb()
    .prepare('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?')
    .get(authReq.teamId, authReq.user.id)) as { role: string } | undefined;
  if (!m || m.role !== 'lead') { res.status(403).json({ error: 'Requires admin or team lead role' }); return false; }
  return true;
}

async function ownProvider(req: Request, res: Response): Promise<Record<string, unknown> | null> {
  const authReq = req as AuthenticatedRequest;
  const row = (await getDb()
    .prepare('SELECT * FROM enrichment_providers WHERE id = ? AND team_id = ?')
    .get(req.params['id'], authReq.teamId)) as Record<string, unknown> | undefined;
  if (!row) { res.status(404).json({ error: 'Provider not found' }); return null; }
  return row;
}

// ── Catalog of built-in presets (for the admin UI's picker) ───────────────────
router.get('/catalog', (_req: Request, res: Response) => {
  res.json({
    catalog: CATALOG.map((c) => ({ kind: c.kind, name: c.name, keyLabel: c.keyLabel, docsUrl: c.docsUrl, config: c.config })),
  });
});

// ── Provider CRUD ─────────────────────────────────────────────────────────────
router.get('/providers', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!authReq.teamId) { res.status(400).json({ error: 'X-Team-Id header required' }); return; }
  const rows = (await getDb().prepare(
    `SELECT id, name, kind, enabled, config, last_status, last_used_at, created_at, updated_at,
            (api_key IS NOT NULL AND api_key <> '') AS has_key
     FROM enrichment_providers WHERE team_id = ? ORDER BY created_at ASC`,
  ).all(authReq.teamId)) as Array<Record<string, unknown>>;
  res.json({ providers: rows });
});

router.post('/providers', async (req: Request, res: Response) => {
  if (!(await requireAdminOrLead(req, res))) return;
  const authReq = req as AuthenticatedRequest;
  const { name, kind, apiKey, config, enabled } = req.body as
    { name?: string; kind?: string; apiKey?: string; config?: unknown; enabled?: boolean };

  const k = (kind ?? '').trim();
  if (!k) { res.status(400).json({ error: 'kind is required' }); return; }
  const preset = catalogEntry(k);
  if (k !== 'custom' && !preset) { res.status(400).json({ error: `Unknown provider kind "${k}"` }); return; }

  // Catalog presets seed their config; custom providers must supply one.
  const cfg = config ?? preset?.config;
  if (!cfg) { res.status(400).json({ error: 'config is required for a custom provider' }); return; }
  const parsed = parseConfig(typeof cfg === 'string' ? cfg : JSON.stringify(cfg));
  if (!parsed.url) { res.status(400).json({ error: 'config.url is required' }); return; }
  if (parsed.supports.length === 0) { res.status(400).json({ error: 'config.supports must list at least one indicator type' }); return; }

  const displayName = (name ?? preset?.name ?? k).trim();
  const id = crypto.randomUUID();
  const now = Date.now();
  await getDb().prepare(
    `INSERT INTO enrichment_providers (id, team_id, name, kind, enabled, api_key, config, created_by, created_at, updated_at)
     VALUES (?,?,?,?,?,?,?,?,?,?)`,
  ).run(id, authReq.teamId, displayName, k, enabled === false ? 0 : 1,
        apiKey?.trim() || null, JSON.stringify(parsed), authReq.user.id, now, now);

  res.json({ ok: true, id });
});

router.patch('/providers/:id', async (req: Request, res: Response) => {
  if (!(await requireAdminOrLead(req, res))) return;
  const row = await ownProvider(req, res);
  if (!row) return;
  const { name, apiKey, config, enabled } = req.body as
    { name?: string; apiKey?: string; config?: unknown; enabled?: boolean };

  const updates: string[] = [];
  const params: unknown[] = [];
  if (name !== undefined && name.trim()) { updates.push('name = ?'); params.push(name.trim()); }
  if (enabled !== undefined) { updates.push('enabled = ?'); params.push(enabled ? 1 : 0); }
  // Never persist the mask back over a real key (same rule as settings.ts).
  if (apiKey !== undefined && apiKey !== MASKED) { updates.push('api_key = ?'); params.push(apiKey.trim() || null); }
  if (config !== undefined) {
    const parsed = parseConfig(typeof config === 'string' ? config : JSON.stringify(config));
    if (!parsed.url) { res.status(400).json({ error: 'config.url is required' }); return; }
    updates.push('config = ?'); params.push(JSON.stringify(parsed));
  }
  if (updates.length === 0) {
    // A request carrying only the masked key is a deliberate "leave it alone",
    // not an error — the edit form always submits the field.
    const touched = name !== undefined || enabled !== undefined || apiKey !== undefined || config !== undefined;
    if (touched) { res.json({ ok: true }); return; }
    res.status(400).json({ error: 'No fields to update' });
    return;
  }
  updates.push('updated_at = ?'); params.push(Date.now(), req.params['id']);

  await getDb().prepare(`UPDATE enrichment_providers SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  // Config/key changes invalidate anything cached under the old settings.
  await invalidateProviderCache(req.params['id'] as string);
  res.json({ ok: true });
});

router.delete('/providers/:id', async (req: Request, res: Response) => {
  if (!(await requireAdminOrLead(req, res))) return;
  const row = await ownProvider(req, res);
  if (!row) return;
  await getDb().prepare('DELETE FROM enrichment_providers WHERE id = ?').run(req.params['id']);
  res.json({ ok: true });
});

// ── Test a provider against a sample indicator ────────────────────────────────
router.post('/providers/:id/test', async (req: Request, res: Response) => {
  if (!(await requireAdminOrLead(req, res))) return;
  const authReq = req as AuthenticatedRequest;
  const row = await ownProvider(req, res);
  if (!row) return;

  const cfg = parseConfig(String(row.config));
  const { type, value } = req.body as { type?: string; value?: string };
  const t = (type ?? cfg.supports[0] ?? '').trim();
  const v = (value ?? '').trim();
  if (!t || !v) { res.status(400).json({ error: 'type and value are required to test' }); return; }

  // Bypass the cache so Test always exercises the real endpoint.
  const provider = providerFromRow({
    id: String(row.id), name: String(row.name), kind: String(row.kind),
    api_key: (row.api_key as string) ?? null, config: String(row.config),
  });
  if (!provider.supports(t)) { res.status(400).json({ error: `This provider does not support ${t}` }); return; }

  const settings = await loadMergedSettings(authReq.teamId);
  const result = await provider.enrich({ type: t, value: normalizeIocValue(t, v), teamId: authReq.teamId, settings });

  await getDb().prepare('UPDATE enrichment_providers SET last_status = ?, last_used_at = ? WHERE id = ?')
    .run(result.status, Date.now(), row.id);

  res.json({ result });
});

// ── Indicator lookup (any team member) ────────────────────────────────────────
router.get('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const type = ((req.query['type'] as string) || '').trim();
  const value = ((req.query['value'] as string) || '').trim();
  if (!type || !value) { res.status(400).json({ error: 'type and value are required' }); return; }

  // Enrich the canonical (refanged, normalized) form so defanged input works.
  const norm = normalizeIocValue(type, value);
  const settings = await loadMergedSettings(authReq.teamId);
  const providers = await enrichIndicator({ type, value: norm, teamId: authReq.teamId, settings });

  res.json({
    type,
    value: norm,
    providers,
    /** True when at least one enabled provider handles this indicator type. */
    anyRegistered: (await providersFor(authReq.teamId, type)).length > 0,
    /** Every enabled provider (any type) — lets the UI explain what's available. */
    registered: (await loadProviders(authReq.teamId)).map((p) => ({ id: p.id, name: p.name, requiredSettings: p.requiredSettings })),
  });
});

export default router;
