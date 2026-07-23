/**
 * Built-in enrichment provider presets.
 *
 * A catalog entry is just a NAMED PRESET of the same `HttpProviderConfig` a
 * Custom HTTP provider uses — so there is one executor, and adding a vendor here
 * is a single object with no new code path. Admins pick a preset in the Admin
 * panel and supply an API key; the preset's config is copied onto the row so
 * they can still tweak it afterwards.
 *
 * Templating tokens available in `url`, `headers` and `link`:
 *   {value}         canonical (refanged, lowercased) indicator
 *   {value_enc}     URL-encoded {value}
 *   {value_b64url}  base64url of {value}, no padding (VirusTotal URL lookups)
 *   {api_key}       the row's stored key
 * `summary` and each fact `path` read from the JSON response by dot path.
 */

export interface FactSpec {
  label: string;
  path: string;
  tone?: 'neutral' | 'good' | 'warn' | 'bad';
}

export interface HttpProviderConfig {
  /** ioc_type values this provider handles. */
  supports: string[];
  url: string;
  headers?: Record<string, string>;
  /** Headline template; may embed {dot.path} values from the response. */
  summary?: string;
  facts?: FactSpec[];
  /** Deep link to the vendor's page for this indicator. */
  link?: string;
  /** HTTP statuses meaning "nothing known" rather than an error. */
  notFound?: number[];
}

export interface CatalogEntry {
  kind: string;
  name: string;
  /** Shown in the admin UI to explain what the key is for. */
  keyLabel: string;
  docsUrl?: string;
  config: HttpProviderConfig;
}

export const CATALOG: CatalogEntry[] = [
  {
    kind: 'virustotal',
    name: 'VirusTotal',
    keyLabel: 'VirusTotal API key (v3)',
    docsUrl: 'https://docs.virustotal.com/reference/overview',
    config: {
      supports: ['ipv4', 'ipv6', 'domain', 'md5', 'sha1', 'sha256'],
      // ip_addresses / domains / files share a shape; the executor picks the
      // path segment from the indicator type via {vt_path}.
      url: 'https://www.virustotal.com/api/v3/{vt_path}/{value_enc}',
      headers: { 'x-apikey': '{api_key}' },
      summary: '{data.attributes.last_analysis_stats.malicious} of {data.attributes.last_analysis_stats.harmless} engines flagged this',
      facts: [
        { label: 'Malicious', path: 'data.attributes.last_analysis_stats.malicious', tone: 'bad' },
        { label: 'Suspicious', path: 'data.attributes.last_analysis_stats.suspicious', tone: 'warn' },
        { label: 'Reputation', path: 'data.attributes.reputation' },
        { label: 'Country', path: 'data.attributes.country' },
      ],
      link: 'https://www.virustotal.com/gui/search/{value_enc}',
      notFound: [404],
    },
  },
  {
    kind: 'abuseipdb',
    name: 'AbuseIPDB',
    keyLabel: 'AbuseIPDB API key',
    docsUrl: 'https://docs.abuseipdb.com/',
    config: {
      supports: ['ipv4', 'ipv6'],
      url: 'https://api.abuseipdb.com/api/v2/check?ipAddress={value_enc}&maxAgeInDays=90',
      headers: { Key: '{api_key}' },
      summary: 'Abuse confidence {data.abuseConfidenceScore}%',
      facts: [
        { label: 'Confidence', path: 'data.abuseConfidenceScore', tone: 'bad' },
        { label: 'Total reports', path: 'data.totalReports' },
        { label: 'ISP', path: 'data.isp' },
        { label: 'Country', path: 'data.countryCode' },
        { label: 'Last reported', path: 'data.lastReportedAt' },
      ],
      link: 'https://www.abuseipdb.com/check/{value_enc}',
      notFound: [404],
    },
  },
  {
    kind: 'shodan',
    name: 'Shodan',
    keyLabel: 'Shodan API key',
    docsUrl: 'https://developer.shodan.io/api',
    config: {
      supports: ['ipv4', 'ipv6'],
      url: 'https://api.shodan.io/shodan/host/{value_enc}?key={api_key}',
      summary: '{org} — {os}',
      facts: [
        { label: 'Org', path: 'org' },
        { label: 'ISP', path: 'isp' },
        { label: 'Country', path: 'country_name' },
        { label: 'Open ports', path: 'ports' },
        { label: 'Last update', path: 'last_update' },
      ],
      link: 'https://www.shodan.io/host/{value_enc}',
      notFound: [404],
    },
  },
  {
    kind: 'urlscan',
    name: 'urlscan.io',
    keyLabel: 'urlscan.io API key',
    docsUrl: 'https://urlscan.io/docs/api/',
    config: {
      supports: ['domain', 'url', 'ipv4'],
      url: 'https://urlscan.io/api/v1/search/?q={value_enc}&size=1',
      headers: { 'API-Key': '{api_key}' },
      summary: '{total} recent scan(s)',
      facts: [
        { label: 'Results', path: 'total' },
        { label: 'Last scan', path: 'results.0.task.time' },
        { label: 'Verdict', path: 'results.0.verdicts.overall.malicious', tone: 'bad' },
      ],
      link: 'https://urlscan.io/search/#{value_enc}',
      notFound: [404],
    },
  },
];

export function catalogEntry(kind: string): CatalogEntry | undefined {
  return CATALOG.find((c) => c.kind === kind);
}

/** VirusTotal splits its API by indicator class; resolve the path segment. */
export function vtPathFor(type: string): string {
  if (type === 'ipv4' || type === 'ipv6') return 'ip_addresses';
  if (type === 'domain') return 'domains';
  return 'files'; // md5 / sha1 / sha256
}
