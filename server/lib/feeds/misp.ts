/** MISP events connector (via /events/restSearch). */
import { fetchWithTimeout, type FeedConnector, type FeedItem, type FeedRow } from './types.js';

interface MispAttribute {
  type?: string;
  value?: string;
  category?: string;
}
interface MispEvent {
  uuid?: string;
  info?: string;
  date?: string;
  threat_level_id?: string;
  Attribute?: MispAttribute[];
  Tag?: Array<{ name?: string }>;
}

function describe(e: MispEvent): string {
  const parts: string[] = [];
  if (e.info) parts.push(e.info);
  if (e.threat_level_id) parts.push(`Threat level: ${e.threat_level_id}`);
  if (e.Tag?.length) parts.push(`Tags: ${e.Tag.map((t) => t.name).filter(Boolean).join(', ')}`);
  const attrs = (e.Attribute ?? []).filter((a) => a.type && a.value).slice(0, 200);
  if (attrs.length) {
    parts.push('\nAttributes:');
    for (const a of attrs) parts.push(`  ${a.type}: ${a.value}`);
  }
  return parts.join('\n');
}

export const mispConnector: FeedConnector = {
  async fetchItems(feed: FeedRow): Promise<FeedItem[]> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    };
    // MISP uses the raw key in Authorization (no "Bearer").
    if (feed.auth_token) headers.Authorization = feed.auth_token;

    let extra: Record<string, unknown> = {};
    try {
      extra = JSON.parse(feed.config || '{}').mispFilters ?? {};
    } catch { /* ignore */ }

    const base = feed.url.replace(/\/+$/, '');
    const res = await fetchWithTimeout(`${base}/events/restSearch`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ returnFormat: 'json', limit: Math.max(feed.max_items, 10), ...extra }),
    });
    const body = (await res.json()) as { response?: Array<{ Event?: MispEvent }> };
    const events = body.response ?? [];

    return events
      .map((wrap) => wrap.Event)
      .filter((e): e is MispEvent => !!e)
      .map((e) => ({
        sourceId: e.uuid ?? `${e.info ?? ''}@${e.date ?? ''}`,
        title: e.info || `MISP event ${e.uuid ?? ''}`,
        content: describe(e),
        publishedAt: e.date ? Date.parse(e.date) || undefined : undefined,
      }));
  },
};
