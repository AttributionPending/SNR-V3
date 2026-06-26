/**
 * LLM Provider abstraction — allows switching between Anthropic and OpenAI-compatible
 * endpoints (Ollama, LM Studio, vLLM, Azure OpenAI, etc.) without changing business logic.
 */

import logger from '../logger.js';
import { readSecret } from '../secrets.js';

export interface JsonSchema {
  type: string;
  properties?: Record<string, unknown>;
  required?: string[];
  [key: string]: unknown;
}

export interface LLMProvider {
  /**
   * Send a prompt and receive structured JSON output matching the given schema.
   * @param systemPrompt  System-level instructions
   * @param userPrompt    The user message / analysis prompt
   * @param toolName      Logical name for the tool (used by Anthropic's tool_choice; included as context for OpenAI)
   * @param toolDescription Short description of the expected output
   * @param schema        JSON Schema describing the expected output shape
   * @param onStream      Optional callback for streaming partial output (Anthropic streams partial JSON; OpenAI-compatible does not)
   */
  analyze<T = unknown>(
    systemPrompt: string,
    userPrompt: string,
    toolName: string,
    toolDescription: string,
    schema: JsonSchema,
    onStream?: (chunk: string) => void
  ): Promise<T>;
}

export type ProviderType = 'anthropic' | 'openai-compatible';

// ── Retry configuration ─────────────────────────────────────────────────────

/** HTTP status codes that are transient and safe to retry */
const RETRYABLE_STATUS_CODES = new Set([429, 500, 502, 503, 529]);

/** HTTP status codes that indicate a non-retryable client error */
const NON_RETRYABLE_STATUS_CODES = new Set([400, 401, 403, 404]);

/** Default timeout for LLM calls in milliseconds (configurable via LLM_TIMEOUT env var) */
const DEFAULT_TIMEOUT_MS = 120_000;

/** Maximum number of retry attempts */
const MAX_RETRIES = 3;

/** Base delay for exponential backoff in milliseconds (1s, 2s, 4s) */
const BASE_DELAY_MS = 1000;

export interface RetryOptions {
  /** Maximum number of retries (default: 3) */
  maxRetries?: number;
  /** Base delay in ms for exponential backoff (default: 1000) */
  baseDelayMs?: number;
  /** Request timeout in ms (default: LLM_TIMEOUT env var or 120000) */
  timeoutMs?: number;
  /** Optional callback invoked before each retry with the attempt number and max */
  onRetry?: (attempt: number, maxAttempts: number, error: Error) => void;
}

/**
 * Extract an HTTP status code from an error, if present.
 * Works with Anthropic SDK errors (`.status`) and OpenAI SDK errors (`.status`).
 */
function getStatusFromError(err: unknown): number | undefined {
  if (err && typeof err === 'object') {
    const e = err as Record<string, unknown>;
    if (typeof e.status === 'number') return e.status;
    // Some errors nest status inside error.response
    if (e.response && typeof e.response === 'object') {
      const resp = e.response as Record<string, unknown>;
      if (typeof resp.status === 'number') return resp.status;
    }
  }
  return undefined;
}

/**
 * Determine whether an error is transient (worth retrying).
 */
function isRetryableError(err: unknown): boolean {
  const status = getStatusFromError(err);

  // Non-retryable status codes — fail immediately
  if (status !== undefined && NON_RETRYABLE_STATUS_CODES.has(status)) {
    return false;
  }

  // Explicitly retryable status codes
  if (status !== undefined && RETRYABLE_STATUS_CODES.has(status)) {
    return true;
  }

  // Timeout / abort errors
  if (err instanceof DOMException && err.name === 'AbortError') return true;
  if (err instanceof Error) {
    const msg = err.message.toLowerCase();
    if (msg.includes('timeout') || msg.includes('aborted')) return true;
    // Network-level transient errors
    if (msg.includes('econnreset') || msg.includes('socket hang up') || msg.includes('etimedout')) return true;
  }

  return false;
}

/**
 * Wrap an async function with retry logic using exponential backoff.
 * Non-retryable errors (400, 401, 403, 404) propagate immediately.
 * Timeout is enforced via AbortController if supported by the inner function.
 */
export async function withRetry<T>(
  fn: (signal?: AbortSignal) => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const maxRetries = options.maxRetries ?? MAX_RETRIES;
  const baseDelay = options.baseDelayMs ?? BASE_DELAY_MS;
  const timeoutMs = options.timeoutMs ?? (
    process.env.LLM_TIMEOUT ? parseInt(process.env.LLM_TIMEOUT, 10) * 1000 : DEFAULT_TIMEOUT_MS
  );

  let lastError: Error | undefined;

  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    // Set up timeout via AbortController
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const result = await fn(controller.signal);
      clearTimeout(timer);
      return result;
    } catch (err) {
      clearTimeout(timer);
      lastError = err instanceof Error ? err : new Error(String(err));

      // Enhance timeout errors with a clear message
      if (controller.signal.aborted) {
        lastError = new Error(
          `LLM request timed out after ${timeoutMs / 1000}s. ` +
          `Increase LLM_TIMEOUT env var (in seconds) or reduce input size.`
        );
      }

      // Non-retryable — fail immediately
      if (!isRetryableError(err) && !controller.signal.aborted) {
        throw lastError;
      }

      // If we have retries left, wait and try again
      if (attempt <= maxRetries) {
        const delayMs = baseDelay * Math.pow(2, attempt - 1); // 1s, 2s, 4s
        const status = getStatusFromError(err);
        logger.warn(
          { attempt, maxRetries: maxRetries + 1, delayMs, status, error: lastError.message },
          `LLM call failed (attempt ${attempt}/${maxRetries + 1}), retrying in ${delayMs / 1000}s`
        );
        options.onRetry?.(attempt, maxRetries + 1, lastError);
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }
  }

  // All retries exhausted
  throw new Error(
    `LLM call failed after ${maxRetries + 1} attempts. Last error: ${lastError?.message ?? 'unknown'}`
  );
}

// ── Provider with retry ─────────────────────────────────────────────────────

/**
 * Wraps an LLMProvider with automatic retry + timeout logic.
 * The onRetry callback allows callers (e.g. SSE streams) to notify clients of retry status.
 */
export class RetryableProvider implements LLMProvider {
  constructor(
    private inner: LLMProvider,
    private retryOptions: RetryOptions = {}
  ) {}

  async analyze<T = unknown>(
    systemPrompt: string,
    userPrompt: string,
    toolName: string,
    toolDescription: string,
    schema: JsonSchema,
    onStream?: (chunk: string) => void
  ): Promise<T> {
    return withRetry<T>(
      // Note: The Anthropic/OpenAI SDKs manage their own connections and don't accept
      // an external AbortSignal for streaming. The timeout in withRetry will abort the
      // promise race, causing the outer catch to fire.
      (_signal?: AbortSignal) =>
        this.inner.analyze<T>(systemPrompt, userPrompt, toolName, toolDescription, schema, onStream),
      this.retryOptions
    );
  }
}

// ── Provider factory ────────────────────────────────────────────────────────

/**
 * Instantiate the correct LLM provider based on settings.
 * Lazy-imports provider modules to avoid loading unused SDKs.
 * The returned provider is wrapped with retry + timeout logic.
 */
export async function getProvider(
  settings: Record<string, string>,
  retryOptions?: RetryOptions
): Promise<LLMProvider> {
  const providerType = (settings.llm_provider || 'anthropic') as ProviderType;
  let inner: LLMProvider;

  if (providerType === 'openai-compatible') {
    const baseUrl = settings.api_base_url?.trim();
    if (!baseUrl) {
      throw new Error('api_base_url is required for openai-compatible provider. Set it in Settings → LLM Provider.');
    }
    const { OpenAIProvider } = await import('./openai-provider.js');
    const contextWindow = settings.context_window ? parseInt(settings.context_window, 10) : 32768;
    inner = new OpenAIProvider({
      baseUrl,
      apiKey: (settings.api_key?.trim() && settings.api_key.trim() !== '••••••••') ? settings.api_key.trim() : 'no-key',
      model: settings.model_name?.trim() || 'default',
      contextWindow: isNaN(contextWindow) ? 32768 : contextWindow,
    });
  } else {
    // Default: Anthropic
    const settingsKey = settings.api_key?.trim();
    const apiKey = (settingsKey && settingsKey !== '••••••••') ? settingsKey : readSecret('ANTHROPIC_API_KEY');
    if (!apiKey) {
      throw new Error('ANTHROPIC_API_KEY not configured. Set it in .env or Settings → LLM Provider.');
    }
    const model = settings.model_name?.trim() || process.env.CLAUDE_MODEL || 'claude-sonnet-4-6';
    const { AnthropicProvider } = await import('./anthropic-provider.js');
    inner = new AnthropicProvider({ apiKey, model });
  }

  // Wrap with retry logic
  return new RetryableProvider(inner, retryOptions);
}
