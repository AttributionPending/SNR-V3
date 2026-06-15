/**
 * Authentication utility functions — password hashing and JWT token management.
 * Designed for SSO extensibility: JWT payload is provider-agnostic.
 */

import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { getDb } from '../db/database.js';
import { readSecret } from './secrets.js';
import logger from './logger.js';

const SALT_ROUNDS = 12;
const TOKEN_EXPIRY = '24h';
const REFRESH_EXPIRY = '7d';

/**
 * Resolve the JWT signing secret.
 * - Always prefers an explicit secret from `JWT_SECRET` / `JWT_SECRET_FILE`.
 * - In production an explicit secret is REQUIRED — we never auto-generate one
 *   (a generated secret would invalidate all tokens on restart and is hard to
 *   rotate/replicate across instances).
 * - In development, falls back to a value persisted in the settings table so
 *   tokens survive restarts without any configuration.
 */
export function getJwtSecret(): string {
  const explicit = readSecret('JWT_SECRET');
  if (explicit) return explicit;

  if (process.env.NODE_ENV === 'production') {
    throw new Error('JWT_SECRET (or JWT_SECRET_FILE) must be set in production');
  }

  const db = getDb();
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get('_jwt_secret') as { value: string } | undefined;
  if (row?.value) return row.value;

  // Dev only: auto-generate and persist
  const secret = crypto.randomBytes(64).toString('hex');
  const now = Date.now();
  db.prepare('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)').run('_jwt_secret', secret, now);
  return secret;
}

export interface JwtPayload {
  sub: string;       // user.id
  email: string;
  role: 'admin' | 'analyst' | 'viewer';
  type: 'access' | 'refresh';
  jti: string;       // unique token ID for revocation
  exp?: number;      // expiration (set by jwt.sign)
}

/** Hash a plaintext password with bcrypt. */
export async function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain, SALT_ROUNDS);
}

/** Verify a plaintext password against a bcrypt hash. */
export async function verifyPassword(plain: string, hash: string): Promise<boolean> {
  return bcrypt.compare(plain, hash);
}

/** Validate a plaintext password meets complexity requirements. */
export function validatePasswordStrength(password: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (password.length < 10) errors.push('Password must be at least 10 characters');
  if (!/[A-Z]/.test(password)) errors.push('Must contain an uppercase letter');
  if (!/[a-z]/.test(password)) errors.push('Must contain a lowercase letter');
  if (!/\d/.test(password)) errors.push('Must contain a number');
  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~]/.test(password)) errors.push('Must contain a special character');
  // Common password check
  const common = ['password', 'changeme', '12345678', 'qwerty', 'letmein', 'admin123', 'welcome'];
  if (common.some(c => password.toLowerCase().includes(c))) errors.push('Password is too common');
  return { valid: errors.length === 0, errors };
}

/** Sign a short-lived access token (24h). */
export function signAccessToken(user: { id: string; email: string; role: string }): string {
  const secret = getJwtSecret();
  return jwt.sign(
    { sub: user.id, email: user.email, role: user.role, type: 'access', jti: crypto.randomUUID() } as JwtPayload,
    secret,
    { expiresIn: TOKEN_EXPIRY, algorithm: 'HS256' }
  );
}

/** Sign a longer-lived refresh token (7d). */
export function signRefreshToken(user: { id: string; email: string; role: string }): string {
  const secret = getJwtSecret();
  return jwt.sign(
    { sub: user.id, email: user.email, role: user.role, type: 'refresh', jti: crypto.randomUUID() } as JwtPayload,
    secret,
    { expiresIn: REFRESH_EXPIRY, algorithm: 'HS256' }
  );
}

/** Verify and decode a JWT token. Throws on invalid/expired. */
export function verifyToken(token: string): JwtPayload {
  const secret = getJwtSecret();
  return jwt.verify(token, secret, { algorithms: ['HS256'] }) as JwtPayload;
}

// ── Token revocation ──────────────────────────────────────────────────────

/** Add a token's JTI to the revocation blacklist. */
export function revokeToken(jti: string, expiresAt: number): void {
  const db = getDb();
  db.prepare('INSERT OR IGNORE INTO revoked_tokens (jti, revoked_at, expires_at) VALUES (?, ?, ?)')
    .run(jti, Date.now(), expiresAt);
}

/** Check whether a token's JTI has been revoked. */
export function isTokenRevoked(jti: string): boolean {
  const db = getDb();
  const row = db.prepare('SELECT 1 FROM revoked_tokens WHERE jti = ?').get(jti);
  return row !== undefined;
}

/** Remove expired entries from the revoked_tokens table (housekeeping). */
export function cleanupRevokedTokens(): void {
  const db = getDb();
  const result = db.prepare('DELETE FROM revoked_tokens WHERE expires_at < ?').run(Date.now());
  if (result.changes > 0) {
    logger.info(`Cleaned up ${result.changes} expired revoked-token entries`);
  }
}
