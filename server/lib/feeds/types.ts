/** Shared types for threat-intel feed connectors. */
import { safeRequest, type SafeResponse } from '../enrichment/egress.js';

export interface FeedRow {
  id: string;
  team_id: string;
  name: string;
  type: 'taxii' | 'misp' | 'rss';
  url: string;
  auth_token: string | null;
  config: string; // JSON string
  audience: string;
  tags: string; // JSON array string
  cadence_minutes: number;
  max_items: number;
  enabled: number;
  last_polled_at: number | null;
  last_status: string | null;
  /** 1 when this feed is a self-hosted server on a private network (opt-in). */
  allow_internal?: number;
}

/** A normalized item from any feed source. */
export interface FeedItem {
  /** Stable identifier from the source (guid / STIX id / event uuid) — used for dedupe. */
  sourceId: string;
  title: string;
  /** Plain-text content fed to the analysis pipeline. */
  content: string;
  publishedAt?: number;
}

export interface FeedConnector {
  fetchItems(feed: FeedRow): Promise<FeedItem[]>;
}

/**
 * Fetch a feed source through the shared SSRF-guarded egress.
 *
 * Feed URLs are admin-supplied, so the same policy as enrichment applies:
 * public https by default, with loopback and cloud-metadata destinations
 * refused outright. A feed explicitly marked `allow_internal` may additionally
 * reach private ranges over http — the opt-in for self-hosted MISP/TAXII.
 *
 * Throws on non-2xx, matching the previous helper so connector error handling
 * is unchanged. Feed payloads (RSS/STIX bundles) are larger than enrichment
 * responses, hence the higher byte cap.
 */
export async function fetchFeed(
  feed: Pick<FeedRow, 'url' | 'allow_internal'>,
  url: string,
  init: { method?: 'GET' | 'POST'; headers?: Record<string, string>; body?: string } = {},
  timeoutMs = 20_000,
): Promise<SafeResponse> {
  const res = await safeRequest(url, {
    ...init,
    timeoutMs,
    maxBytes: 8 * 1024 * 1024,
    allowInternal: feed.allow_internal === 1,
  });
  if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status} from ${url}`);
  return res;
}

/** Strip HTML tags and collapse whitespace for clean analysis input. */
export function stripHtml(html: string): string {
  return html
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ')
    .trim();
}
