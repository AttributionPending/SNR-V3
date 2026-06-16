/** Shared types for threat-intel feed connectors. */

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

/** Fetch with a timeout (default 20s). Throws on non-2xx. */
export async function fetchWithTimeout(
  url: string,
  init: RequestInit = {},
  timeoutMs = 20_000,
): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
    return res;
  } finally {
    clearTimeout(t);
  }
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
