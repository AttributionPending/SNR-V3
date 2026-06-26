/**
 * Brand profiles: per-team, reusable white-label email identities (theme + sender).
 * Resolution order for a session: its selected profile → the team default profile
 * → the built-in SNR theme + default sender.
 */
import crypto from 'crypto';
import { getDb } from '../db/database.js';
import { resolveTheme, type EmailTheme } from './email-theme.js';

export interface EmailSender {
  fromName: string;        // display name ('' => analyst name)
  fromEmail: string;       // '' => analyst email
  replyTo: string;         // '' => none
  cc: string;              // comma-separated
  bcc: string;             // comma-separated
  preheader: string;       // inbox preview text
  subjectTemplate: string; // '' => default subject behavior
}

export const DEFAULT_SENDER: EmailSender = {
  fromName: '', fromEmail: '', replyTo: '', cc: '', bcc: '', preheader: '', subjectTemplate: '',
};

export interface BrandProfileRow {
  id: string;
  team_id: string;
  name: string;
  is_default: number;
  theme: string;
  sender: string;
  created_at: number;
  updated_at: number;
}

export interface ResolvedBrand {
  profileId: string | null;
  name: string;
  theme: Partial<EmailTheme>; // raw overrides (renderer applies resolveTheme)
  sender: EmailSender;
}

function safeParse<T>(json: string | null | undefined, fallback: T): T {
  if (!json) return fallback;
  try { return { ...fallback, ...(JSON.parse(json) as object) } as T; } catch { return fallback; }
}

// ── CRUD ─────────────────────────────────────────────────────────────────────

export async function listBrandProfiles(teamId: string): Promise<BrandProfileRow[]> {
  const db = getDb();
  return (await db
    .prepare('SELECT * FROM brand_profiles WHERE team_id = ? ORDER BY is_default DESC, name ASC')
    .all(teamId)) as BrandProfileRow[];
}

export async function getBrandProfile(id: string, teamId: string): Promise<BrandProfileRow | undefined> {
  const db = getDb();
  return (await db
    .prepare('SELECT * FROM brand_profiles WHERE id = ? AND team_id = ?')
    .get(id, teamId)) as BrandProfileRow | undefined;
}

export async function createBrandProfile(input: {
  teamId: string;
  name: string;
  theme?: Partial<EmailTheme>;
  sender?: Partial<EmailSender>;
  isDefault?: boolean;
  createdBy: string;
}): Promise<{ id: string }> {
  const db = getDb();
  const id = crypto.randomUUID();
  const now = Date.now();
  if (input.isDefault) {
    await db.prepare('UPDATE brand_profiles SET is_default = 0 WHERE team_id = ?').run(input.teamId);
  }
  await db
    .prepare(
      `INSERT INTO brand_profiles (id, team_id, name, is_default, theme, sender, created_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      id, input.teamId, input.name.trim(), input.isDefault ? 1 : 0,
      JSON.stringify(input.theme ?? {}), JSON.stringify({ ...DEFAULT_SENDER, ...(input.sender ?? {}) }),
      input.createdBy, now, now,
    );
  return { id };
}

export async function updateBrandProfile(
  id: string,
  teamId: string,
  patch: { name?: string; theme?: Partial<EmailTheme>; sender?: Partial<EmailSender>; isDefault?: boolean },
): Promise<boolean> {
  const db = getDb();
  const existing = await getBrandProfile(id, teamId);
  if (!existing) return false;
  if (patch.isDefault) {
    await db.prepare('UPDATE brand_profiles SET is_default = 0 WHERE team_id = ?').run(teamId);
  }
  const name = patch.name?.trim() ?? existing.name;
  const theme = patch.theme !== undefined ? JSON.stringify(patch.theme) : existing.theme;
  const sender = patch.sender !== undefined
    ? JSON.stringify({ ...DEFAULT_SENDER, ...safeParse(existing.sender, DEFAULT_SENDER), ...patch.sender })
    : existing.sender;
  const isDefault = patch.isDefault !== undefined ? (patch.isDefault ? 1 : 0) : existing.is_default;
  await db
    .prepare('UPDATE brand_profiles SET name = ?, theme = ?, sender = ?, is_default = ?, updated_at = ? WHERE id = ? AND team_id = ?')
    .run(name, theme, sender, isDefault, Date.now(), id, teamId);
  return true;
}

export async function deleteBrandProfile(id: string, teamId: string): Promise<boolean> {
  const db = getDb();
  const res = await db.prepare('DELETE FROM brand_profiles WHERE id = ? AND team_id = ?').run(id, teamId);
  return res.changes > 0;
}

// ── Resolution ───────────────────────────────────────────────────────────────

/** Resolve the brand to use for a session: explicit profile → team default →
 *  built-in SNR (empty theme + default sender). */
export async function resolveBrandForSession(sessionId: string, teamId: string): Promise<ResolvedBrand> {
  const db = getDb();
  const session = (await db
    .prepare('SELECT brand_profile_id FROM sessions WHERE id = ?')
    .get(sessionId)) as { brand_profile_id: string | null } | undefined;

  let row: BrandProfileRow | undefined;
  if (session?.brand_profile_id) {
    row = await getBrandProfile(session.brand_profile_id, teamId);
  }
  if (!row) {
    row = (await db
      .prepare('SELECT * FROM brand_profiles WHERE team_id = ? AND is_default = 1 LIMIT 1')
      .get(teamId)) as BrandProfileRow | undefined;
  }
  if (!row) {
    return { profileId: null, name: 'SNR (default)', theme: {}, sender: { ...DEFAULT_SENDER } };
  }
  return {
    profileId: row.id,
    name: row.name,
    theme: safeParse<Partial<EmailTheme>>(row.theme, {}),
    sender: safeParse<EmailSender>(row.sender, DEFAULT_SENDER),
  };
}

export async function setSessionBrandProfile(sessionId: string, teamId: string, profileId: string | null): Promise<void> {
  const db = getDb();
  // Validate the profile belongs to the team (when setting one).
  if (profileId) {
    const p = await getBrandProfile(profileId, teamId);
    if (!p) throw new Error('Brand profile not found');
  }
  await db.prepare('UPDATE sessions SET brand_profile_id = ?, updated_at = ? WHERE id = ?').run(profileId, Date.now(), sessionId);
}
