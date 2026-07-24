/** TAXII 2.1 collection poll connector (STIX 2.1 objects). */
import { fetchFeed, type FeedConnector, type FeedItem, type FeedRow } from './types.js';

interface StixObject {
  id?: string;
  type?: string;
  name?: string;
  description?: string;
  pattern?: string;
  labels?: string[];
  modified?: string;
  created?: string;
}

/**
 * feed.url may be the collection objects endpoint directly, or a TAXII API root
 * combined with config.collectionId → `${url}/collections/${id}/objects/`.
 */
function objectsUrl(feed: FeedRow): string {
  let collectionId: string | undefined;
  try {
    collectionId = JSON.parse(feed.config || '{}').collectionId;
  } catch { /* ignore */ }
  if (collectionId) {
    const base = feed.url.replace(/\/+$/, '');
    return `${base}/collections/${collectionId}/objects/`;
  }
  return feed.url;
}

function describe(o: StixObject): string {
  const parts: string[] = [];
  if (o.type) parts.push(`Type: ${o.type}`);
  if (o.name) parts.push(`Name: ${o.name}`);
  if (o.labels?.length) parts.push(`Labels: ${o.labels.join(', ')}`);
  if (o.pattern) parts.push(`Pattern: ${o.pattern}`);
  if (o.description) parts.push(`\n${o.description}`);
  return parts.join('\n');
}

export const taxiiConnector: FeedConnector = {
  async fetchItems(feed: FeedRow): Promise<FeedItem[]> {
    const headers: Record<string, string> = { Accept: 'application/taxii+json;version=2.1' };
    if (feed.auth_token) headers.Authorization = `Bearer ${feed.auth_token}`;
    const res = await fetchFeed(feed, objectsUrl(feed), { headers });
    const body = (res.json() ?? {}) as { objects?: StixObject[] };
    const objects = body.objects ?? [];

    return objects
      // Skip relationship/marking plumbing — keep substantive intel objects.
      .filter((o) => o.type && !['relationship', 'marking-definition'].includes(o.type))
      .map((o) => {
        const title = o.name || `${o.type} ${o.id ?? ''}`.trim();
        return {
          sourceId: `${o.id ?? ''}@${o.modified || o.created || ''}`,
          title,
          content: describe(o),
          publishedAt: o.modified || o.created ? Date.parse(o.modified || o.created || '') || undefined : undefined,
        };
      });
  },
};
