/**
 * Machine authentication for the integration API (/api/v1).
 *
 * Accepts `Authorization: Bearer snr_…` or `X-API-Key: snr_…`, resolves the key
 * to a service account, and populates the SAME `AuthenticatedRequest` shape the
 * JWT middleware uses — so team scoping and downstream handlers work unchanged.
 * Adds `scopes` and `apiKeyId` for per-key authorization and rate limiting.
 */
import type { Request, Response, NextFunction } from 'express';
import { resolveApiKey } from '../lib/api-keys.js';
import type { AuthenticatedRequest } from './auth.js';
import logger from '../lib/logger.js';

export interface ServiceAuthRequest extends AuthenticatedRequest {
  scopes: string[];
  apiKeyId: string;
  rateLimitPerMin: number;
}

function extractToken(req: Request): string | undefined {
  const header = req.headers.authorization;
  if (header?.startsWith('Bearer ')) return header.slice(7).trim();
  const xkey = req.headers['x-api-key'];
  if (typeof xkey === 'string' && xkey) return xkey.trim();
  return undefined;
}

export async function requireApiKey(req: Request, res: Response, next: NextFunction): Promise<void> {
  const token = extractToken(req);
  if (!token) {
    res.status(401).json({ error: 'API key required (Authorization: Bearer snr_… or X-API-Key)' });
    return;
  }

  try {
    const resolved = await resolveApiKey(token);
    if (!resolved) {
      res.status(401).json({ error: 'Invalid, expired, or revoked API key' });
      return;
    }

    const sreq = req as ServiceAuthRequest;
    sreq.user = {
      id: resolved.account.id,
      email: `svc:${resolved.account.name}`,
      displayName: resolved.account.name,
      role: resolved.account.role,
      teamIds: [resolved.account.team_id],
    };
    sreq.teamId = resolved.account.team_id;
    sreq.scopes = resolved.scopes;
    sreq.apiKeyId = resolved.keyId;
    sreq.rateLimitPerMin = resolved.rateLimitPerMin;
    next();
  } catch (err) {
    logger.error({ err }, 'API key auth error');
    res.status(503).json({ error: 'Service temporarily unavailable' });
  }
}

/** Require a specific permission scope. Use AFTER requireApiKey. */
export function requireScope(scope: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const sreq = req as ServiceAuthRequest;
    if (!sreq.scopes?.includes(scope)) {
      res.status(403).json({ error: `API key missing required scope: ${scope}` });
      return;
    }
    next();
  };
}
