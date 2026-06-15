import pino from 'pino';
import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import { httpRequestsTotal } from './metrics.js';

// ── Logger instance ──────────────────────────────────────────────────────────

const isDev = process.env.NODE_ENV !== 'production';

export const logger = pino({
  level: process.env.LOG_LEVEL ?? (isDev ? 'debug' : 'info'),
  transport: isDev
    ? { target: 'pino-pretty', options: { colorize: true, translateTime: 'HH:MM:ss', ignore: 'pid,hostname' } }
    : undefined,
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'password',
      'password_hash',
      'api_key',
      'ANTHROPIC_API_KEY',
      'token',
      'refresh_token',
    ],
    casing: 'any',
    remove: false,
  },
  serializers: {
    err: pino.stdSerializers.err,
  },
});

// ── Request logging middleware ────────────────────────────────────────────────

interface AuthenticatedRequest extends Request {
  user?: { id: string; email: string; displayName: string; role: string };
  teamId?: string;
  requestId?: string;
}

export function requestLogger(req: Request, res: Response, next: NextFunction): void {
  const authReq = req as AuthenticatedRequest;
  const requestId = (req.headers['x-request-id'] as string) ?? crypto.randomUUID();
  authReq.requestId = requestId;
  res.setHeader('X-Request-Id', requestId);

  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;
    try { httpRequestsTotal.inc({ method: req.method, status: res.statusCode }); } catch { /* metrics best-effort */ }
    const logData = {
      requestId,
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      duration,
      userId: authReq.user?.id,
      teamId: authReq.teamId,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    };

    if (res.statusCode >= 500) {
      logger.error(logData, 'request error');
    } else if (res.statusCode >= 400) {
      logger.warn(logData, 'request warning');
    } else {
      logger.info(logData, 'request');
    }
  });

  next();
}

export default logger;
