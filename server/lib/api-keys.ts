/**
 * Machine-authentication helpers: service accounts and their API keys.
 *
 * Tokens are high-entropy (`snr_` + 32 random bytes, base64url). Only a SHA-256
 * hash is stored, so a leaked database cannot reveal usable keys. The plaintext
 * token is shown exactly once, at mint time.
 */
import crypto from 'crypto';
import { getDb } from '../db/database.js';

export const VALID_SCOPES = ['analyze:write', 'sessions:read', 'export:read'] as const;
export type Scope = (typeof VALID_SCOPES)[number];

export interface ServiceAccount {
  id: string;
  name: string;
  team_id: string;
  role: 'analyst' | 'viewer';
  disabled: number;
}

export interface ResolvedApiKey {
  keyId: string;
  scopes: string[];
  rateLimitPerMin: number;
  account: ServiceAccount;
}

/** SHA-256 hex of the full token (constant-time compare not needed for lookup). */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/** Generate a new opaque API token. */
function generateToken(): { token: string; prefix: string } {
  const token = `snr_${crypto.randomBytes(32).toString('base64url')}`;
  return { token, prefix: token.slice(0, 12) };
}

export async function createServiceAccount(input: {
  name: string;
  teamId: string;
  role?: 'analyst' | 'viewer';
  createdBy: string;
}): Promise<{ id: string }> {
  const db = getDb();
  const id = crypto.randomUUID();
  const now = Date.now();
  await db
    .prepare(
      `INSERT INTO service_accounts (id, name, team_id, role, created_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .run(id, input.name.trim(), input.teamId, input.role ?? 'analyst', input.createdBy, now, now);
  return { id };
}

export async function listServiceAccounts(teamId?: string): Promise<Array<Record<string, unknown>>> {
  const db = getDb();
  const rows = teamId
    ? ((await db
        .prepare(
          `SELECT sa.*, (SELECT COUNT(*) FROM api_keys k WHERE k.service_account_id = sa.id AND k.revoked_at IS NULL) AS active_keys
           FROM service_accounts sa WHERE sa.team_id = ? ORDER BY sa.created_at DESC`
        )
        .all(teamId)) as Array<Record<string, unknown>>)
    : ((await db
        .prepare(
          `SELECT sa.*, (SELECT COUNT(*) FROM api_keys k WHERE k.service_account_id = sa.id AND k.revoked_at IS NULL) AS active_keys
           FROM service_accounts sa ORDER BY sa.created_at DESC`
        )
        .all()) as Array<Record<string, unknown>>);
  return rows;
}

export async function setServiceAccountDisabled(id: string, disabled: boolean): Promise<number> {
  const db = getDb();
  const res = await db
    .prepare('UPDATE service_accounts SET disabled = ?, updated_at = ? WHERE id = ?')
    .run(disabled ? 1 : 0, Date.now(), id);
  return res.changes;
}

/** Mint a new key for a service account. Returns the plaintext token ONCE. */
export async function mintApiKey(input: {
  serviceAccountId: string;
  name: string;
  scopes: string[];
  rateLimitPerMin?: number;
  createdBy: string;
  expiresAt?: number | null;
}): Promise<{ id: string; token: string; prefix: string }> {
  const db = getDb();
  const id = crypto.randomUUID();
  const { token, prefix } = generateToken();
  const scopes = input.scopes.filter((s) => (VALID_SCOPES as readonly string[]).includes(s));
  const now = Date.now();
  await db
    .prepare(
      `INSERT INTO api_keys (id, service_account_id, name, prefix, key_hash, scopes, rate_limit_per_min, created_by, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      id,
      input.serviceAccountId,
      input.name.trim(),
      prefix,
      hashToken(token),
      JSON.stringify(scopes),
      input.rateLimitPerMin ?? 60,
      input.createdBy,
      now,
      input.expiresAt ?? null
    );
  return { id, token, prefix };
}

export async function listApiKeys(serviceAccountId: string): Promise<Array<Record<string, unknown>>> {
  const db = getDb();
  return (await db
    .prepare(
      `SELECT id, name, prefix, scopes, rate_limit_per_min, created_at, last_used_at, expires_at, revoked_at
       FROM api_keys WHERE service_account_id = ? ORDER BY created_at DESC`
    )
    .all(serviceAccountId)) as Array<Record<string, unknown>>;
}

export async function revokeApiKey(keyId: string): Promise<number> {
  const db = getDb();
  const res = await db
    .prepare('UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL')
    .run(Date.now(), keyId);
  return res.changes;
}

/**
 * Resolve a presented token to a service identity, or null if invalid/revoked/
 * expired/disabled. Updates last_used_at (best-effort).
 */
export async function resolveApiKey(token: string): Promise<ResolvedApiKey | null> {
  if (!token || !token.startsWith('snr_')) return null;
  const db = getDb();
  const key = (await db
    .prepare(
      `SELECT id, service_account_id, scopes, rate_limit_per_min, expires_at, revoked_at FROM api_keys WHERE key_hash = ?`
    )
    .get(hashToken(token))) as
    | {
        id: string;
        service_account_id: string;
        scopes: string;
        rate_limit_per_min: number;
        expires_at: number | null;
        revoked_at: number | null;
      }
    | undefined;
  if (!key || key.revoked_at) return null;
  if (key.expires_at && Date.now() > key.expires_at) return null;

  const account = (await db
    .prepare('SELECT id, name, team_id, role, disabled FROM service_accounts WHERE id = ?')
    .get(key.service_account_id)) as ServiceAccount | undefined;
  if (!account || account.disabled) return null;

  // Best-effort last-used tracking.
  void db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(Date.now(), key.id);

  let scopes: string[] = [];
  try {
    scopes = JSON.parse(key.scopes || '[]');
  } catch {
    scopes = [];
  }

  return { keyId: key.id, scopes, rateLimitPerMin: key.rate_limit_per_min, account };
}
