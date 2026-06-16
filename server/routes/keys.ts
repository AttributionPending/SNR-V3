/**
 * Admin management of service accounts and API keys (human/JWT auth).
 * Mounted behind requireAuth + requireRole('admin') + requireTeamMember, so
 * accounts are scoped to the admin's active team. Plaintext keys are returned
 * exactly once, at mint time.
 */
import { Router } from 'express';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';
import { getDb, appendAuditLog } from '../db/database.js';
import {
  VALID_SCOPES,
  createServiceAccount,
  listServiceAccounts,
  setServiceAccountDisabled,
  mintApiKey,
  listApiKeys,
  revokeApiKey,
} from '../lib/api-keys.js';
import logger from '../lib/logger.js';

const router = Router();

/** Confirm a service account exists and belongs to the admin's team. */
async function ownAccount(req: Request, res: Response): Promise<{ id: string; name: string } | null> {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const acct = (await db
    .prepare('SELECT id, name FROM service_accounts WHERE id = ? AND team_id = ?')
    .get(req.params.id, authReq.teamId)) as { id: string; name: string } | undefined;
  if (!acct) {
    res.status(404).json({ error: 'Service account not found' });
    return null;
  }
  return acct;
}

// GET /api/keys/scopes — list the valid permission scopes.
router.get('/scopes', (_req, res) => {
  res.json({ scopes: VALID_SCOPES });
});

// GET /api/keys/service-accounts — list accounts in the admin's team.
router.get('/service-accounts', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!authReq.teamId) {
    res.status(400).json({ error: 'X-Team-Id header required to scope service accounts' });
    return;
  }
  res.json({ serviceAccounts: await listServiceAccounts(authReq.teamId) });
});

// POST /api/keys/service-accounts — create an account.
router.post('/service-accounts', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!authReq.teamId) {
    res.status(400).json({ error: 'X-Team-Id header required' });
    return;
  }
  const { name, role } = req.body as { name?: string; role?: 'analyst' | 'viewer' };
  if (!name?.trim()) {
    res.status(400).json({ error: 'name is required' });
    return;
  }
  if (role && !['analyst', 'viewer'].includes(role)) {
    res.status(400).json({ error: 'role must be analyst or viewer' });
    return;
  }
  const { id } = await createServiceAccount({
    name,
    teamId: authReq.teamId,
    role: role ?? 'analyst',
    createdBy: authReq.user.id,
  });
  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    action: 'service_account_created',
    details: `name="${name.trim()}" role=${role ?? 'analyst'}`,
  });
  res.status(201).json({ id });
});

// PATCH /api/keys/service-accounts/:id — enable/disable.
router.patch('/service-accounts/:id', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const acct = await ownAccount(req, res);
  if (!acct) return;
  if (typeof req.body.disabled === 'boolean') {
    await setServiceAccountDisabled(acct.id, req.body.disabled);
    appendAuditLog({
      analyst_name: authReq.user.displayName,
      user_id: authReq.user.id,
      action: req.body.disabled ? 'service_account_disabled' : 'service_account_enabled',
      details: `name="${acct.name}"`,
    });
  }
  res.json({ ok: true });
});

// GET /api/keys/service-accounts/:id/keys — list a account's keys (metadata).
router.get('/service-accounts/:id/keys', async (req: Request, res: Response) => {
  const acct = await ownAccount(req, res);
  if (!acct) return;
  res.json({ keys: await listApiKeys(acct.id) });
});

// POST /api/keys/service-accounts/:id/keys — mint a key (returns token once).
router.post('/service-accounts/:id/keys', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const acct = await ownAccount(req, res);
  if (!acct) return;
  const { name, scopes, rateLimitPerMin, expiresAt } = req.body as {
    name?: string;
    scopes?: string[];
    rateLimitPerMin?: number;
    expiresAt?: number | null;
  };
  if (!name?.trim()) {
    res.status(400).json({ error: 'name is required' });
    return;
  }
  const requested = Array.isArray(scopes) ? scopes : [];
  const invalid = requested.filter((s) => !(VALID_SCOPES as readonly string[]).includes(s));
  if (invalid.length > 0) {
    res.status(400).json({ error: `Invalid scopes: ${invalid.join(', ')}` });
    return;
  }
  const minted = await mintApiKey({
    serviceAccountId: acct.id,
    name,
    scopes: requested.length > 0 ? requested : [...VALID_SCOPES],
    rateLimitPerMin,
    createdBy: authReq.user.id,
    expiresAt: expiresAt ?? null,
  });
  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    action: 'api_key_minted',
    details: `account="${acct.name}" key="${name.trim()}" prefix=${minted.prefix}`,
  });
  logger.info({ accountId: acct.id, keyId: minted.id }, 'API key minted');
  // The token is returned ONCE — the client must store it now.
  res.status(201).json({ id: minted.id, token: minted.token, prefix: minted.prefix });
});

// POST /api/keys/:keyId/revoke — revoke a key.
router.post('/:keyId/revoke', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  // Ensure the key belongs to an account in the admin's team.
  const key = (await db
    .prepare(
      `SELECT k.id FROM api_keys k JOIN service_accounts sa ON sa.id = k.service_account_id
       WHERE k.id = ? AND sa.team_id = ?`
    )
    .get(req.params.keyId, authReq.teamId)) as { id: string } | undefined;
  if (!key) {
    res.status(404).json({ error: 'API key not found' });
    return;
  }
  const changed = await revokeApiKey(key.id);
  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    action: 'api_key_revoked',
    details: `keyId=${key.id}`,
  });
  res.json({ ok: true, revoked: changed > 0 });
});

export default router;
