/** RSS / Atom advisory feed connector. */
import { XMLParser } from 'fast-xml-parser';
import crypto from 'crypto';
import { fetchWithTimeout, stripHtml, type FeedConnector, type FeedItem, type FeedRow } from './types.js';

const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_', trimValues: true });

function asArray<T>(v: T | T[] | undefined): T[] {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

// fast-xml-parser may return a node as a string or as an object with #text.
function text(node: unknown): string {
  if (node == null) return '';
  if (typeof node === 'string') return node;
  if (typeof node === 'object') {
    const o = node as Record<string, unknown>;
    if (typeof o['#text'] === 'string') return o['#text'];
    if (typeof o['@_href'] === 'string') return o['@_href'];
  }
  return String(node);
}

export const rssConnector: FeedConnector = {
  async fetchItems(feed: FeedRow): Promise<FeedItem[]> {
    const headers: Record<string, string> = { Accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml' };
    if (feed.auth_token) headers.Authorization = `Bearer ${feed.auth_token}`;
    const res = await fetchWithTimeout(feed.url, { headers });
    const xml = await res.text();
    const doc = parser.parse(xml) as Record<string, any>;

    const items: FeedItem[] = [];

    // RSS 2.0: rss.channel.item[]
    const rssItems = asArray(doc?.rss?.channel?.item);
    for (const it of rssItems) {
      const title = stripHtml(text(it.title));
      const body = stripHtml(text(it['content:encoded']) || text(it.description) || '');
      const sourceId = text(it.guid) || text(it.link) || crypto.createHash('sha256').update(title + body).digest('hex');
      const pub = it.pubDate ? Date.parse(text(it.pubDate)) : NaN;
      items.push({ sourceId, title: title || '(untitled)', content: `${title}\n\n${body}`.trim(), publishedAt: Number.isNaN(pub) ? undefined : pub });
    }

    // Atom: feed.entry[]
    const atomEntries = asArray(doc?.feed?.entry);
    for (const e of atomEntries) {
      const title = stripHtml(text(e.title));
      const body = stripHtml(text(e.content) || text(e.summary) || '');
      const sourceId = text(e.id) || text(e.link) || crypto.createHash('sha256').update(title + body).digest('hex');
      const pub = e.updated ? Date.parse(text(e.updated)) : NaN;
      items.push({ sourceId, title: title || '(untitled)', content: `${title}\n\n${body}`.trim(), publishedAt: Number.isNaN(pub) ? undefined : pub });
    }

    return items;
  },
};
