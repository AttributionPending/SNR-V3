// Uses Node.js built-in sqlite (Node 22.5+) — no native compilation required
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import { DatabaseSync } from 'node:sqlite';
import path from 'path';
import crypto from 'crypto';
import logger from '../lib/logger.js';
import { readSecret } from '../lib/secrets.js';

const DB_PATH = process.env.DB_PATH || './snr.db';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let db: any;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function getDb(): any {
  if (!db) {
    db = new DatabaseSync(path.resolve(DB_PATH));
    db.exec('PRAGMA journal_mode = WAL');
    db.exec('PRAGMA foreign_keys = ON');
    initSchema(db);
  }
  return db;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function initSchema(db: any): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      incident_id TEXT,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      severity TEXT,
      audience TEXT,
      version INTEGER DEFAULT 1,
      input_hash TEXT,
      status TEXT DEFAULT 'pending'
    );

    CREATE TABLE IF NOT EXISTS session_inputs (
      id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
      input_type TEXT NOT NULL CHECK(input_type IN ('siem','log','text')),
      content TEXT NOT NULL,
      filename TEXT,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS analysis_results (
      id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
      version INTEGER NOT NULL DEFAULT 1,
      result_json TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      analyst_overrides TEXT
    );

    CREATE TABLE IF NOT EXISTS analyst_notes (
      id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
      content TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp INTEGER NOT NULL,
      analyst_name TEXT NOT NULL,
      session_id TEXT,
      action TEXT NOT NULL,
      input_hash TEXT,
      outputs_generated TEXT,
      techniques_identified TEXT,
      details TEXT
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);

    -- ── Multi-user tables ──────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'analyst' CHECK(role IN ('admin','analyst','viewer')),
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      last_login_at INTEGER,
      disabled INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS teams (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS team_members (
      team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('lead','member')),
      joined_at INTEGER NOT NULL,
      PRIMARY KEY (team_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS team_settings (
      team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
      key TEXT NOT NULL,
      value TEXT NOT NULL,
      updated_at INTEGER NOT NULL,
      PRIMARY KEY (team_id, key)
    );

    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);

    -- ── Token revocation (session blacklist) ─────────────────────────────────
    CREATE TABLE IF NOT EXISTS revoked_tokens (
      jti TEXT PRIMARY KEY,
      revoked_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_revoked_expires ON revoked_tokens(expires_at);

    -- Foreign key indexes for query performance
    CREATE INDEX IF NOT EXISTS idx_session_inputs_session ON session_inputs(session_id);
    CREATE INDEX IF NOT EXISTS idx_analysis_results_session ON analysis_results(session_id);
    CREATE INDEX IF NOT EXISTS idx_analyst_notes_session ON analyst_notes(session_id);
    CREATE INDEX IF NOT EXISTS idx_audit_log_session ON audit_log(session_id);

    -- ── Threat Actor Grouping ─────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS threat_actors (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      aliases TEXT DEFAULT '[]',
      motivation TEXT,
      attribution_confidence TEXT CHECK(attribution_confidence IN ('High','Medium','Low')),
      intrusion_set TEXT,
      campaign_name TEXT,
      malware_families TEXT DEFAULT '[]',
      description TEXT DEFAULT '',
      team_id TEXT REFERENCES teams(id),
      created_by TEXT REFERENCES users(id),
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS session_threat_actors (
      session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
      threat_actor_id TEXT NOT NULL REFERENCES threat_actors(id) ON DELETE CASCADE,
      link_type TEXT NOT NULL DEFAULT 'auto' CHECK(link_type IN ('auto','manual')),
      linked_at INTEGER NOT NULL,
      linked_by TEXT REFERENCES users(id),
      PRIMARY KEY (session_id, threat_actor_id)
    );

    CREATE TABLE IF NOT EXISTS threat_actor_merges (
      id TEXT PRIMARY KEY,
      source_actor_id TEXT NOT NULL,
      target_actor_id TEXT NOT NULL REFERENCES threat_actors(id),
      source_actor_name TEXT NOT NULL,
      merged_by TEXT REFERENCES users(id),
      merged_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_threat_actors_team ON threat_actors(team_id);
    CREATE INDEX IF NOT EXISTS idx_threat_actors_name ON threat_actors(name COLLATE NOCASE);
    CREATE INDEX IF NOT EXISTS idx_sta_threat_actor ON session_threat_actors(threat_actor_id);
    CREATE INDEX IF NOT EXISTS idx_sta_session ON session_threat_actors(session_id);
  `);

  // ── Schema migrations for existing databases ────────────────────────────
  // ALTER TABLE throws if column already exists — wrap each in try-catch
  const alterStatements = [
    'ALTER TABLE sessions ADD COLUMN team_id TEXT REFERENCES teams(id)',
    'ALTER TABLE sessions ADD COLUMN created_by TEXT REFERENCES users(id)',
    'ALTER TABLE audit_log ADD COLUMN user_id TEXT REFERENCES users(id)',
    'ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE users ADD COLUMN locked_until INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE users ADD COLUMN password_changed_at INTEGER NOT NULL DEFAULT 0',
    "ALTER TABLE sessions ADD COLUMN tags TEXT DEFAULT '[]'",
    'ALTER TABLE sessions ADD COLUMN deleted_at INTEGER',
  ];
  for (const sql of alterStatements) {
    try { db.exec(sql); } catch { /* column already exists */ }
  }

  // Create index on new column (safe — IF NOT EXISTS)
  try { db.exec('CREATE INDEX IF NOT EXISTS idx_sessions_team ON sessions(team_id)'); } catch { /* */ }
  try { db.exec('CREATE INDEX IF NOT EXISTS idx_sessions_created_by ON sessions(created_by)'); } catch { /* */ }
  try { db.exec('CREATE INDEX IF NOT EXISTS idx_sessions_deleted ON sessions(deleted_at)'); } catch { /* */ }

  // ── Purge soft-deleted sessions past the retention window (7 days) ───────
  try {
    const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
    const stale = db.prepare('SELECT id FROM sessions WHERE deleted_at IS NOT NULL AND deleted_at < ?').all(cutoff) as Array<{ id: string }>;
    for (const { id } of stale) {
      db.prepare('DELETE FROM session_inputs WHERE session_id = ?').run(id);
      db.prepare('DELETE FROM analysis_results WHERE session_id = ?').run(id);
      db.prepare('DELETE FROM analyst_notes WHERE session_id = ?').run(id);
      db.prepare('DELETE FROM sessions WHERE id = ?').run(id);
    }
    if (stale.length > 0) {
      logger.info(`Purged ${stale.length} soft-deleted session(s) past 7-day retention`);
    }
  } catch { /* purge is best-effort */ }

  // Seed default settings if not present
  const defaults: Record<string, string> = {
    org_name: process.env.ANALYST_ORG ?? 'Security Operations',
    analyst_name: process.env.ANALYST_NAME ?? 'CTI Analyst',
    analyst_email: process.env.ANALYST_EMAIL ?? 'cti-analyst@organization.com',
    default_tlp: 'AMBER',
    email_header_text: 'SIGNAL TO NOISE',
    email_footer_text: "This brief was generated by SNR (Signal-to-Noise). Handle per your organization\u2019s data classification policy.",
    email_signature: '',
    email_custom_preamble: '',
    email_font_family: 'Arial',
    email_body_font_size: '14',
    cc_purple_team: '',
    cc_soc: '',
    cc_red_team: '',
    cc_dr: '',
    cc_general: '',
    custom_intro_purple_team: '',
    custom_intro_soc: '',
    custom_intro_red_team: '',
    custom_intro_dr: '',
    custom_intro_general: '',
    org_evaluation_criteria: '',
    org_detection_context: '',
    // Editable audience prompt overrides (empty = use built-in default)
    audience_prompt_purple_team: '',
    audience_prompt_soc: '',
    audience_prompt_red_team: '',
    audience_prompt_dr: '',
    audience_prompt_general: '',
    // Prompt engineering overrides (empty = use built-in defaults)
    system_prompt_override: '',
    phase1_instructions_override: '',
    phase2_template_override: '',
    // Custom audience definitions (JSON array of {id, label, prompt})
    custom_audiences: '',
    // Email section visibility toggles
    email_show_observations: 'true',
    email_show_techniques: 'true',
    email_show_affected_assets: 'true',
    email_show_actions: 'true',
    email_show_iocs: 'true',
    email_show_next_steps: 'true',
    // Branding
    email_primary_color: '#1d4ed8',
    email_secondary_color: '#0a0f1e',
    email_logo_data: '',
    // Email body layout template (empty = use built-in DEFAULT_EMAIL_TEMPLATE)
    email_template: '',
    // CTI Report template (empty = use built-in DEFAULT_REPORT_TEMPLATE)
    report_template: '',
    // LLM Provider configuration
    llm_provider: 'anthropic',  // 'anthropic' | 'openai-compatible'
    api_base_url: '',           // e.g. http://localhost:11434/v1 for Ollama
    api_key: '',                // provider API key; falls back to ANTHROPIC_API_KEY env var
    model_name: '',             // e.g. llama3.2; falls back to CLAUDE_MODEL env var
  };
  const now = Date.now();
  for (const [key, value] of Object.entries(defaults)) {
    db.prepare('INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?, ?, ?)').run(key, value, now);
  }
}

// ── Bootstrap admin ────────────────────────────────────────────────────────

/**
 * Create the initial admin user and default team on first run.
 * Called from server startup. Idempotent — skips if users already exist.
 * Returns true if bootstrap was performed.
 */
export async function bootstrapAdmin(): Promise<boolean> {
  const db = getDb();
  const userCount = (db.prepare('SELECT COUNT(*) as c FROM users').get() as { c: number }).c;
  if (userCount > 0) return false;

  const email = readSecret('A2N_ADMIN_EMAIL');
  const password = readSecret('A2N_ADMIN_PASSWORD');
  const displayName = process.env.ANALYST_NAME || 'Admin';

  if (!email || !password) {
    logger.warn('\n⚠  No users exist and A2N_ADMIN_EMAIL / A2N_ADMIN_PASSWORD are not set.');
    logger.warn('   Set these in your .env file to create the initial SNR admin account.\n');
    return false;
  }

  // Lazy-import to avoid circular dependency at module load time
  const { hashPassword, validatePasswordStrength } = await import('../lib/auth-utils.js');

  // Validate admin password meets complexity requirements
  const pwCheck = validatePasswordStrength(password);
  if (!pwCheck.valid) {
    logger.error(`\n✗ Admin password does not meet complexity requirements:`);
    for (const err of pwCheck.errors) logger.error(`  - ${err}`);
    logger.error('  Update A2N_ADMIN_PASSWORD in .env and restart SNR.\n');
    return false;
  }

  const now = Date.now();
  const adminId = crypto.randomUUID();
  const teamId = crypto.randomUUID();
  const passwordHash = await hashPassword(password);

  // Create admin user
  db.prepare(`
    INSERT INTO users (id, email, password_hash, display_name, role, created_at, updated_at)
    VALUES (?, ?, ?, ?, 'admin', ?, ?)
  `).run(adminId, email.toLowerCase(), passwordHash, displayName, now, now);

  // Create default team
  db.prepare(`
    INSERT INTO teams (id, name, description, created_at, updated_at)
    VALUES (?, 'Default Team', 'Auto-created during initial setup', ?, ?)
  `).run(teamId, now, now);

  // Add admin as team lead
  db.prepare(`
    INSERT INTO team_members (team_id, user_id, role, joined_at)
    VALUES (?, ?, 'lead', ?)
  `).run(teamId, adminId, now);

  // Migrate existing sessions to the default team
  db.prepare('UPDATE sessions SET team_id = ?, created_by = ? WHERE team_id IS NULL').run(teamId, adminId);

  // Migrate existing audit log entries
  db.prepare('UPDATE audit_log SET user_id = ? WHERE user_id IS NULL').run(adminId);

  logger.info(`✓ Admin account created: ${email}`);
  logger.info(`✓ Default Team created. All existing sessions assigned.`);

  return true;
}

// ── Settings helpers ───────────────────────────────────────────────────────

/**
 * Load settings with team-level overrides merged on top of org defaults.
 * If teamId is empty/undefined, returns only global settings.
 */
export function loadMergedSettings(teamId?: string): Record<string, string> {
  const db = getDb();

  // Global (org-wide) settings
  const globalRows = db.prepare('SELECT key, value FROM settings').all() as Array<{ key: string; value: string }>;
  const merged: Record<string, string> = {};
  for (const r of globalRows) merged[r.key] = r.value;

  // Overlay team-specific settings if teamId provided
  if (teamId) {
    const teamRows = db.prepare('SELECT key, value FROM team_settings WHERE team_id = ?').all(teamId) as Array<{ key: string; value: string }>;
    for (const r of teamRows) merged[r.key] = r.value;
  }

  return merged;
}

// ── Audit log ──────────────────────────────────────────────────────────────

export function appendAuditLog(entry: {
  analyst_name: string;
  user_id?: string;
  session_id?: string;
  action: string;
  input_hash?: string;
  outputs_generated?: string[];
  techniques_identified?: string[];
  details?: string;
}): void {
  const db = getDb();
  const stmt = db.prepare(`
    INSERT INTO audit_log (timestamp, analyst_name, user_id, session_id, action, input_hash, outputs_generated, techniques_identified, details)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    Date.now(),
    entry.analyst_name,
    entry.user_id ?? null,
    entry.session_id ?? null,
    entry.action,
    entry.input_hash ?? null,
    entry.outputs_generated ? JSON.stringify(entry.outputs_generated) : null,
    entry.techniques_identified ? JSON.stringify(entry.techniques_identified) : null,
    entry.details ?? null
  );
}
