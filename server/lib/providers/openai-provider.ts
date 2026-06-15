/**
 * OpenAI-compatible provider — works with Ollama, LM Studio, vLLM, Azure OpenAI,
 * and any endpoint that implements the OpenAI chat completions API.
 *
 * Structured output strategy:
 *   1. Uses response_format: { type: 'json_object' } when supported
 *   2. Embeds the JSON schema in the system prompt for models that don't natively enforce schemas
 *   3. Applies jsonrepair as a fallback for minor formatting issues
 *
 * Unlike the Anthropic provider, this does NOT stream partial JSON to the UI.
 * The full response is buffered and parsed after generation completes.
 */

import OpenAI from 'openai';
import { jsonrepair } from 'jsonrepair';
import type { LLMProvider, JsonSchema } from './index.js';

interface OpenAIProviderConfig {
  baseUrl: string;
  apiKey: string;
  model: string;
  contextWindow?: number;
}

export class OpenAIProvider implements LLMProvider {
  private client: OpenAI;
  private model: string;
  private contextWindow: number;

  constructor(config: OpenAIProviderConfig) {
    this.client = new OpenAI({
      baseURL: config.baseUrl,
      apiKey: config.apiKey,
    });
    this.model = config.model;
    this.contextWindow = config.contextWindow ?? 32768;
  }

  async analyze<T = unknown>(
    systemPrompt: string,
    userPrompt: string,
    toolName: string,
    toolDescription: string,
    schema: JsonSchema,
    _onStream?: (chunk: string) => void
  ): Promise<T> {
    // Embed schema in the system prompt so models know what JSON to produce
    const schemaInstructions = [
      '',
      'CRITICAL OUTPUT RULES:',
      '1. Your ENTIRE response must be a single valid JSON object. Nothing else.',
      '2. Do NOT write markdown, explanations, headers, or commentary.',
      '3. Do NOT use code fences (```). Just output raw JSON starting with {',
      '4. Every string value must be properly escaped JSON.',
      `5. The JSON must conform to this schema for tool "${toolName}" (${toolDescription}):`,
      '',
      JSON.stringify(schema, null, 2),
      '',
      'BEGIN your response with { and END with }. No other text.',
    ].join('\n');
    const fullSystemPrompt = systemPrompt + schemaInstructions;

    let stream;
    try {
      stream = await this.client.chat.completions.create({
        model: this.model,
        max_tokens: 16000,
        temperature: 0.2,
        messages: [
          { role: 'system', content: fullSystemPrompt },
          { role: 'user', content: userPrompt },
          { role: 'assistant', content: '{' },
        ],
        response_format: { type: 'json_object' },
        stream: true,
        // Ollama-specific options for performance optimization
        options: this.ollamaOptions(),
      } as Parameters<typeof this.client.chat.completions.create>[0]);
    } catch (err) {
      // Some endpoints don't support response_format — retry without it
      const errMsg = (err as Error).message || '';
      if (errMsg.includes('response_format') || errMsg.includes('json_object')) {
        try {
          stream = await this.client.chat.completions.create({
            model: this.model,
            max_tokens: 16000,
            temperature: 0.2,
            messages: [
              { role: 'system', content: fullSystemPrompt },
              { role: 'user', content: userPrompt },
              { role: 'assistant', content: '{' },
            ],
            stream: true,
            options: this.ollamaOptions(),
          } as Parameters<typeof this.client.chat.completions.create>[0]);
        } catch (retryErr) {
          throw this.wrapError(retryErr);
        }
      } else {
        throw this.wrapError(err);
      }
    }

    // Buffer streamed text tokens — no partial JSON streaming to UI
    const chunks: string[] = [];
    let finishReason: string | null = null;

    for await (const chunk of stream) {
      const delta = chunk.choices?.[0]?.delta?.content;
      if (delta) {
        chunks.push(delta);
      }
      const reason = chunk.choices?.[0]?.finish_reason;
      if (reason) {
        finishReason = reason;
      }
    }

    if (finishReason === 'length') {
      throw new Error('Model response was cut off (max_tokens). Reduce input size or use a model with a larger context window.');
    }

    let rawText = chunks.join('');
    if (!rawText.trim()) {
      throw new Error(`No response received for ${toolName} from ${this.model}`);
    }

    // Prepend the prefilled '{' from the assistant message, but only if
    // the model didn't already start with '{'
    if (!rawText.trimStart().startsWith('{')) {
      rawText = '{' + rawText;
    }

    // Strip markdown code fences if the model wrapped the JSON
    rawText = rawText.replace(/^```(?:json)?\s*\n?/i, '').replace(/\n?```\s*$/i, '').trim();

    // Try to extract JSON object if the model mixed in text before/after
    const jsonMatch = rawText.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      rawText = jsonMatch[0];
    }

    // Parse JSON — jsonrepair fallback for minor issues
    try {
      return JSON.parse(rawText) as T;
    } catch (firstErr) {
      try {
        return JSON.parse(jsonrepair(rawText)) as T;
      } catch {
        throw new Error(`Failed to parse ${toolName} response from ${this.model}: ${(firstErr as Error).message}\n\nRaw output (first 500 chars):\n${rawText.slice(0, 500)}`);
      }
    }
  }

  /**
   * Build Ollama-specific options for performance optimization.
   * These are passed through by Ollama's OpenAI-compatible endpoint
   * and silently ignored by other OpenAI-compatible servers.
   */
  private ollamaOptions(): Record<string, unknown> {
    return {
      num_ctx: this.contextWindow,       // Context window size
      num_batch: 1024,                   // Larger batch = faster prompt processing
      flash_attn: true,                  // Flash Attention — faster, less VRAM for attention
      cache_type_k: 'q8_0',             // Quantize KV cache keys — ~50% VRAM savings
      cache_type_v: 'q8_0',             // Quantize KV cache values — ~50% VRAM savings
    };
  }

  private wrapError(err: unknown): Error {
    const apiErr = err as { status?: number; message?: string };
    const status = apiErr.status;
    const msg = apiErr.message || (err as Error).message;

    if (status === 401 || status === 403) {
      return new Error(`Authentication failed for ${this.client.baseURL} — check your API key.`);
    }
    if (status === 404) {
      return new Error(`Model '${this.model}' not found at ${this.client.baseURL}. Verify the model name is correct and pulled/loaded.`);
    }
    if (status === 429) {
      return new Error('Rate limit reached — wait a moment and try again.');
    }
    if (typeof status === 'number' && status >= 500) {
      return new Error(`Server error (HTTP ${status}) from ${this.client.baseURL}: ${msg}`);
    }
    // Connection errors (Ollama not running, wrong URL, etc.)
    if (msg.includes('ECONNREFUSED') || msg.includes('ENOTFOUND') || msg.includes('fetch failed')) {
      return new Error(`Cannot connect to ${this.client.baseURL} — is the server running? Check your API Base URL in Settings.`);
    }
    return new Error(`LLM API error (HTTP ${status ?? 'unknown'}): ${msg}`);
  }
}
