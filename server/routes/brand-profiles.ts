/**
 * White-label brand profiles (human/JWT auth, team-scoped).
 * Mounted behind requireAuth + requireTeamMember.
 *
 * Read (list/get) is open to any team member so the Email Studio can show the
 * available brands and the per-session selector. Mutations (create/update/delete,
 * and changing a session's brand) require admin or team-lead role — brands are a
 * team-wide identity, not a per-analyst preference.
 */
import { Router } from 'express';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';
import { getDb, appendAuditLog } from '../db/database.js';
import {
  listBrandProfiles,
  getBrandProfile,
  createBrandProfile,
  updateBrandProfile,
  deleteBrandProfile,
  resolveBrandForSession,
  setSessionBrandProfile,
  type EmailSender,
} from '../lib/brand-profiles.js';
import type { EmailTheme } from '../lib/email-theme.js';
import logger from '../lib/logger.js';

const router = Router();

/** Require the caller to be an admin or a lead of the active team. */
async function requireAdminOrLead(req: Request, res: Response): Promise<boolean> {
  const authReq = req as AuthenticatedRequest;
  if (!authReq.teamId) {
    res.status(400).json({ error: 'X-Team-Id header required' });
    return false;
  }
  if (authReq.user.role === 'admin') return true;
  const db = getDb();
  const m = (await db
    .prepare('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?')
    .get(authReq.teamId, authReq.user.id)) as { role: string } | undefined;
  if (!m || m.role !== 'lead') {
    res.status(403).json({ error: 'Requires admin or team lead role' });
    return false;
  }
  return true;
}

function requireTeam(req: Request, res: Response): string | null {
  const authReq = req as AuthenticatedRequest;
  if (!authReq.teamId) {
    res.status(400).json({ error: 'X-Team-Id header required' });
    return null;
  }
  return authReq.teamId;
}

/** Parse an incoming brand-profile body into { theme, sender } partials. */
function parseBrandBody(body: Record<string, unknown>): {
  theme?: Partial<EmailTheme>;
  sender?: Partial<EmailSender>;
} {
  const theme = body.theme && typeof body.theme === 'object' ? (body.theme as Partial<EmailTheme>) : undefined;
  const sender = body.sender && typeof body.sender === 'object' ? (body.sender as Partial<EmailSender>) : undefined;
  return { theme, sender };
}

// GET /api/brand-profiles — list this team's brand profiles.
router.get('/', async (req: Request, res: Response) => {
  const teamId = requireTeam(req, res);
  if (!teamId) return;
  const rows = await listBrandProfiles(teamId);
  // Parse JSON columns so the client gets structured theme/sender.
  res.json({
    profiles: rows.map((r) => ({
      id: r.id,
      name: r.name,
      isDefault: r.is_default === 1,
      theme: safeJson(r.theme, {}),
      sender: safeJson(r.sender, {}),
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    })),
  });
});

function safeJson(s: string, fallback: unknown): unknown {
  try { return JSON.parse(s); } catch { return fallback; }
}

// GET /api/brand-profiles/:id — fetch one profile.
router.get('/:id', async (req: Request, res: Response) => {
  const teamId = requireTeam(req, res);
  if (!teamId) return;
  const row = await getBrandProfile(req.params.id, teamId);
  if (!row) { res.status(404).json({ error: 'Brand profile not found' }); return; }
  res.json({
    id: row.id,
    name: row.name,
    isDefault: row.is_default === 1,
    theme: safeJson(row.theme, {}),
    sender: safeJson(row.sender, {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  });
});

// POST /api/brand-profiles — create a profile.
router.post('/', async (req: Request, res: Response) => {
  if (!(await requireAdminOrLead(req, res))) return;
  const authReq = req as AuthenticatedRequest;
  const teamId = authReq.teamId;
  const body = req.body as Record<string, unknown>;
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  if (!name) { res.status(400).json({ error: 'name is required' }); return; }
  const { theme, sender } = parseBrandBody(body);
  const { id } = await createBrandProfile({
    teamId,
    name,
    theme,
    sender,
    isDefault: body.isDefault === true,
    createdBy: authReq.user.id,
  });
  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    action: 'brand_profile_create',
    details: `Created brand profile "${name}" (${id})`,
  });
  res.status(201).json({ id });
});

// PUT /api/brand-profiles/:id — update a profile.
router.put('/:id', async (req: Request, res: Response) => {
  if (!(await requireAdminOrLead(req, res))) return;
  const authReq = req as AuthenticatedRequest;
  const teamId = authReq.teamId;
  const body = req.body as Record<string, unknown>;
  const { theme, sender } = parseBrandBody(body);
  const patch: { name?: string; theme?: Partial<EmailTheme>; sender?: Partial<EmailSender>; isDefault?: boolean } = {};
  if (typeof body.name === 'string') {
    const n = body.name.trim();
    if (!n) { res.status(400).json({ error: 'name cannot be empty' }); return; }
    patch.name = n;
  }
  if (theme !== undefined) patch.theme = theme;
  if (sender !== undefined) patch.sender = sender;
  if (typeof body.isDefault === 'boolean') patch.isDefault = body.isDefault;
  const ok = await updateBrandProfile(req.params.id, teamId, patch);
  if (!ok) { res.status(404).json({ error: 'Brand profile not found' }); return; }
  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    action: 'brand_profile_update',
    details: `Updated brand profile ${req.params.id}`,
  });
  res.json({ ok: true });
});

// DELETE /api/brand-profiles/:id — remove a profile.
router.delete('/:id', async (req: Request, res: Response) => {
  if (!(await requireAdminOrLead(req, res))) return;
  const authReq = req as AuthenticatedRequest;
  const teamId = authReq.teamId;
  const ok = await deleteBrandProfile(req.params.id, teamId);
  if (!ok) { res.status(404).json({ error: 'Brand profile not found' }); return; }
  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    action: 'brand_profile_delete',
    details: `Deleted brand profile ${req.params.id}`,
  });
  res.json({ ok: true });
});

// GET /api/brand-profiles/session/:sessionId — resolved brand for a session.
router.get('/session/:sessionId', async (req: Request, res: Response) => {
  const teamId = requireTeam(req, res);
  if (!teamId) return;
  const brand = await resolveBrandForSession(req.params.sessionId, teamId);
  res.json(brand);
});

// PUT /api/brand-profiles/session/:sessionId — set a session's brand profile.
// Body: { profileId: string | null }.
router.put('/session/:sessionId', async (req: Request, res: Response) => {
  if (!(await requireAdminOrLead(req, res))) return;
  const authReq = req as AuthenticatedRequest;
  const teamId = authReq.teamId;
  const body = req.body as Record<string, unknown>;
  const profileId = body.profileId === null ? null : (typeof body.profileId === 'string' ? body.profileId : undefined);
  if (profileId === undefined) { res.status(400).json({ error: 'profileId (string or null) is required' }); return; }
  // Verify the session belongs to the team.
  const db = getDb();
  const session = (await db
    .prepare('SELECT id, team_id FROM sessions WHERE id = ? AND deleted_at IS NULL')
    .get(req.params.sessionId)) as { id: string; team_id: string } | undefined;
  if (!session || session.team_id !== teamId) { res.status(404).json({ error: 'Session not found' }); return; }
  try {
    await setSessionBrandProfile(req.params.sessionId, teamId, profileId);
  } catch (err) {
    logger.warn({ err }, 'setSessionBrandProfile failed');
    res.status(400).json({ error: 'Brand profile not found' });
    return;
  }
  res.json({ ok: true });
});

export default router;
