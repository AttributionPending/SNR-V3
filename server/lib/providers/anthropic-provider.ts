/**
 * Anthropic provider — uses @anthropic-ai/sdk with tool_choice for structured JSON output.
 * Streams partial JSON via input_json_delta events.
 *
 * Extracted verbatim from the original claude.ts streamCallWithTool function.
 */

import Anthropic from '@anthropic-ai/sdk';
import { jsonrepair } from 'jsonrepair';
import type { LLMProvider, JsonSchema } from './index.js';

interface AnthropicProviderConfig {
  apiKey: string;
  model: string;
}

export class AnthropicProvider implements LLMProvider {
  private client: Anthropic;
  private model: string;

  constructor(config: AnthropicProviderConfig) {
    this.client = new Anthropic({ apiKey: config.apiKey });
    this.model = config.model;
  }

  async analyze<T = unknown>(
    systemPrompt: string,
    userPrompt: string,
    toolName: string,
    toolDescription: string,
    schema: JsonSchema,
    onStream?: (chunk: string) => void
  ): Promise<T> {
    let stream;
    try {
      stream = await this.client.messages.stream({
        model: this.model,
        max_tokens: 16000,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }],
        tools: [{ name: toolName, description: toolDescription, input_schema: schema as Anthropic.Tool['input_schema'] }],
        tool_choice: { type: 'tool', name: toolName },
      });
    } catch (err) {
      const apiErr = err as Anthropic.APIError;
      const status = apiErr?.status;
      if (status === 401) throw new Error('Invalid Anthropic API key — verify ANTHROPIC_API_KEY in your .env file.');
      if (status === 403) throw new Error('API key lacks permission. Check your Anthropic account plan and model access.');
      if (status === 404) throw new Error(`Model '${this.model}' not found. Pick a valid model in Settings → LLM Provider, or set CLAUDE_MODEL in .env (e.g. claude-sonnet-4-6).`);
      if (status === 429) throw new Error('Anthropic rate limit reached — wait a moment and try again.');
      if (status === 529) throw new Error('Anthropic API is overloaded — try again in a few seconds.');
      throw new Error(`Anthropic API error (HTTP ${status ?? 'unknown'}): ${(err as Error).message}`);
    }

    // Accumulate partial_json fragments ourselves — never rely on SDK's internal JSON.parse
    // The SDK's finalMessage() calls JSON.parse internally and can fail when Claude embeds
    // literal newlines in long string fields.
    const jsonChunks: string[] = [];
    let stopReason: string | null = null;

    for await (const chunk of stream) {
      if (chunk.type === 'content_block_delta' && chunk.delta.type === 'input_json_delta') {
        jsonChunks.push(chunk.delta.partial_json);
        if (onStream) onStream(chunk.delta.partial_json);
      }
      if (chunk.type === 'message_delta') {
        stopReason = chunk.delta.stop_reason ?? null;
      }
    }

    // Also try finalMessage() for stop_reason, but don't let its internal parse failure propagate
    if (!stopReason) {
      try {
        const msg = await stream.finalMessage();
        stopReason = msg.stop_reason;
      } catch {
        // SDK parse failed — we have our own accumulated JSON, continue
      }
    }

    if (stopReason === 'max_tokens') {
      throw new Error('Claude response was cut off (max_tokens). Reduce input size or set a larger CLAUDE_MAX_TOKENS value.');
    }

    const rawJson = jsonChunks.join('');
    if (!rawJson.trim()) {
      throw new Error(`No tool input received for ${toolName}`);
    }

    // Parse with native JSON.parse, fall back to jsonrepair for embedded newlines / minor issues
    try {
      return JSON.parse(rawJson) as T;
    } catch (firstErr) {
      try {
        return JSON.parse(jsonrepair(rawJson)) as T;
      } catch {
        throw new Error(`Failed to parse ${toolName} response: ${(firstErr as Error).message}`);
      }
    }
  }
}
