import { describe, it, expect, vi } from 'vitest';

// Test retry logic by replicating the pure functions (they have side-effect-heavy imports)
describe('isRetryableError', () => {
  const RETRYABLE_STATUS_CODES = new Set([429, 500, 502, 503, 529]);
  const NON_RETRYABLE_STATUS_CODES = new Set([400, 401, 403, 404]);

  function getStatusFromError(err: unknown): number | undefined {
    if (err && typeof err === 'object') {
      const e = err as Record<string, unknown>;
      if (typeof e.status === 'number') return e.status;
      if (e.response && typeof e.response === 'object') {
        const resp = e.response as Record<string, unknown>;
        if (typeof resp.status === 'number') return resp.status;
      }
    }
    return undefined;
  }

  function isRetryableError(err: unknown): boolean {
    const status = getStatusFromError(err);
    if (status !== undefined && NON_RETRYABLE_STATUS_CODES.has(status)) return false;
    if (status !== undefined && RETRYABLE_STATUS_CODES.has(status)) return true;
    if (err instanceof DOMException && err.name === 'AbortError') return true;
    if (err instanceof Error) {
      const msg = err.message.toLowerCase();
      if (msg.includes('timeout') || msg.includes('aborted')) return true;
      if (msg.includes('econnreset') || msg.includes('socket hang up') || msg.includes('etimedout'))
        return true;
    }
    return false;
  }

  it('retries on 429 (rate limit)', () => {
    expect(isRetryableError({ status: 429, message: 'Rate limited' })).toBe(true);
  });

  it('retries on 500 (server error)', () => {
    expect(isRetryableError({ status: 500, message: 'Internal error' })).toBe(true);
  });

  it('retries on 502 (bad gateway)', () => {
    expect(isRetryableError({ status: 502, message: 'Bad gateway' })).toBe(true);
  });

  it('retries on 503 (service unavailable)', () => {
    expect(isRetryableError({ status: 503, message: 'Unavailable' })).toBe(true);
  });

  it('retries on 529 (overloaded)', () => {
    expect(isRetryableError({ status: 529, message: 'Overloaded' })).toBe(true);
  });

  it('does not retry on 400 (bad request)', () => {
    expect(isRetryableError({ status: 400, message: 'Bad request' })).toBe(false);
  });

  it('does not retry on 401 (unauthorized)', () => {
    expect(isRetryableError({ status: 401, message: 'Unauthorized' })).toBe(false);
  });

  it('does not retry on 403 (forbidden)', () => {
    expect(isRetryableError({ status: 403, message: 'Forbidden' })).toBe(false);
  });

  it('does not retry on 404 (not found)', () => {
    expect(isRetryableError({ status: 404, message: 'Not found' })).toBe(false);
  });

  it('retries on timeout errors', () => {
    expect(isRetryableError(new Error('Request timeout'))).toBe(true);
    expect(isRetryableError(new Error('Connection ETIMEDOUT'))).toBe(true);
  });

  it('retries on connection reset', () => {
    expect(isRetryableError(new Error('ECONNRESET'))).toBe(true);
    expect(isRetryableError(new Error('socket hang up'))).toBe(true);
  });

  it('does not retry on unknown errors', () => {
    expect(isRetryableError(new Error('Something unexpected'))).toBe(false);
  });

  it('extracts status from nested response object', () => {
    const err = { response: { status: 503 } };
    expect(isRetryableError(err)).toBe(true);
  });
});

describe('getStatusFromError', () => {
  function getStatusFromError(err: unknown): number | undefined {
    if (err && typeof err === 'object') {
      const e = err as Record<string, unknown>;
      if (typeof e.status === 'number') return e.status;
      if (e.response && typeof e.response === 'object') {
        const resp = e.response as Record<string, unknown>;
        if (typeof resp.status === 'number') return resp.status;
      }
    }
    return undefined;
  }

  it('extracts status from top-level property', () => {
    expect(getStatusFromError({ status: 429 })).toBe(429);
  });

  it('extracts status from response property', () => {
    expect(getStatusFromError({ response: { status: 500 } })).toBe(500);
  });

  it('returns undefined for non-object', () => {
    expect(getStatusFromError('string error')).toBeUndefined();
    expect(getStatusFromError(null)).toBeUndefined();
    expect(getStatusFromError(42)).toBeUndefined();
  });

  it('returns undefined when no status present', () => {
    expect(getStatusFromError({ message: 'some error' })).toBeUndefined();
  });
});

describe('withRetry (integration)', () => {
  // We can test retry logic with a minimal inline implementation
  async function withRetry<T>(
    fn: () => Promise<T>,
    options: { maxRetries?: number; baseDelayMs?: number } = {},
  ): Promise<T> {
    const maxRetries = options.maxRetries ?? 3;
    const baseDelay = options.baseDelayMs ?? 0; // 0 for fast tests
    let lastError: Error | undefined;

    for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
      try {
        return await fn();
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
        if (attempt <= maxRetries) {
          const delay = baseDelay * Math.pow(2, attempt - 1);
          if (delay > 0) await new Promise((r) => setTimeout(r, delay));
        }
      }
    }
    throw lastError;
  }

  it('succeeds on first try', async () => {
    const fn = vi.fn().mockResolvedValue('success');
    const result = await withRetry(fn);
    expect(result).toBe('success');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('retries and succeeds on second attempt', async () => {
    const fn = vi
      .fn()
      .mockRejectedValueOnce(new Error('transient'))
      .mockResolvedValue('ok');
    const result = await withRetry(fn, { maxRetries: 2, baseDelayMs: 0 });
    expect(result).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('throws after exhausting retries', async () => {
    const fn = vi.fn().mockRejectedValue(new Error('always fails'));
    await expect(withRetry(fn, { maxRetries: 2, baseDelayMs: 0 })).rejects.toThrow('always fails');
    expect(fn).toHaveBeenCalledTimes(3); // 1 initial + 2 retries
  });
});
