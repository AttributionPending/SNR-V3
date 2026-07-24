import { describe, it, expect } from 'vitest';
import { getPath, render, parseConfig, providerFromRow } from './http-provider';
import { catalogEntry, vtPathFor } from './catalog';

// A trimmed VirusTotal v3 IP response.
const VT_BODY = {
  data: {
    attributes: {
      last_analysis_stats: { harmless: 70, malicious: 7, suspicious: 2 },
      reputation: -14,
      country: 'US',
    },
  },
};

describe('getPath', () => {
  it('reads nested keys and array indices', () => {
    expect(getPath(VT_BODY, 'data.attributes.reputation')).toBe(-14);
    expect(getPath({ results: [{ task: { time: 'T' } }] }, 'results.0.task.time')).toBe('T');
  });
  it('returns undefined for missing paths without throwing', () => {
    expect(getPath(VT_BODY, 'data.nope.deep')).toBeUndefined();
    expect(getPath(null, 'a.b')).toBeUndefined();
  });
});

describe('render', () => {
  const ctx = { value: '8.8.8.8', apiKey: 'KEY123', type: 'ipv4' };
  it('substitutes indicator and key tokens', () => {
    expect(render('https://x/{vt_path}/{value_enc}', ctx)).toBe('https://x/ip_addresses/8.8.8.8');
    expect(render('{api_key}', ctx)).toBe('KEY123');
    expect(render('{value_b64url}', { ...ctx, value: 'http://a.b' })).toBe(Buffer.from('http://a.b').toString('base64url'));
  });
  it('substitutes response dot-paths when a body is supplied', () => {
    expect(render('{data.attributes.last_analysis_stats.malicious} flagged', ctx, VT_BODY)).toBe('7 flagged');
  });
  it('renders missing paths as an em dash rather than crashing', () => {
    expect(render('{data.missing}', ctx, VT_BODY)).toBe('—');
  });
});

describe('parseConfig', () => {
  it('defaults safely on malformed JSON', () => {
    const c = parseConfig('{not json');
    expect(c.supports).toEqual([]);
    expect(c.url).toBe('');
    expect(c.notFound).toEqual([404]);
  });
});

describe('providerFromRow', () => {
  const vt = catalogEntry('virustotal')!;
  const row = { id: 'p1', name: 'VirusTotal', kind: 'virustotal', api_key: 'K', config: JSON.stringify(vt.config) };

  it('supports exactly the configured indicator types', () => {
    const p = providerFromRow(row);
    expect(p.supports('ipv4')).toBe(true);
    expect(p.supports('sha256')).toBe(true);
    expect(p.supports('filename')).toBe(false);
  });

  it('is unconfigured when the config needs a key and none is stored', () => {
    expect(providerFromRow({ ...row, api_key: null }).isConfigured({})).toBe(false);
    expect(providerFromRow(row).isConfigured({})).toBe(true);
  });

  it('treats a keyless config as configured', () => {
    const keyless = { ...row, api_key: null, config: JSON.stringify({ supports: ['ipv4'], url: 'https://x/{value}' }) };
    expect(providerFromRow(keyless).isConfigured({})).toBe(true);
  });

  it('returns a result (never throws) when the URL is missing', async () => {
    const broken = providerFromRow({ ...row, config: JSON.stringify({ supports: ['ipv4'], url: '' }) });
    const r = await broken.enrich({ type: 'ipv4', value: '8.8.8.8', teamId: 't', settings: {} });
    expect(r.status).toBe('error');
    expect(r.providerName).toBe('VirusTotal');
  });

  it('serves a cached result without touching the network', async () => {
    const cached = { providerId: 'p1', providerName: 'VirusTotal', status: 'ok' as const, summary: 'from cache' };
    const p = providerFromRow(row, { read: async () => cached, write: async () => {} });
    const r = await p.enrich({ type: 'ipv4', value: '8.8.8.8', teamId: 't', settings: {} });
    expect(r.summary).toBe('from cache');
  });

  it('blocks a provider whose URL targets an internal address', async () => {
    const evil = providerFromRow({ ...row, config: JSON.stringify({ supports: ['ipv4'], url: 'https://169.254.169.254/latest/{value}' }) });
    const r = await evil.enrich({ type: 'ipv4', value: '8.8.8.8', teamId: 't', settings: {} });
    expect(r.status).toBe('error');
    expect(r.message).toMatch(/Blocked/);
  });
});

describe('catalog', () => {
  it('routes VirusTotal paths by indicator class', () => {
    expect(vtPathFor('ipv4')).toBe('ip_addresses');
    expect(vtPathFor('domain')).toBe('domains');
    expect(vtPathFor('sha256')).toBe('files');
  });

  it('every preset has a url and supported types, and covers each type it claims', () => {
    for (const c of [catalogEntry('virustotal')!, catalogEntry('abuseipdb')!, catalogEntry('shodan')!, catalogEntry('urlscan')!]) {
      expect(c.config.url).toMatch(/^https:\/\//);
      expect(c.config.supports.length).toBeGreaterThan(0);
      // Any per-type override must itself be a public https endpoint.
      for (const u of Object.values(c.config.urlByType ?? {})) expect(u).toMatch(/^https:\/\//);
    }
  });

  it('urlscan scopes the query to the indicator instead of a loose full-text match', () => {
    const cfg = catalogEntry('urlscan')!.config;
    // A bare q={value} returns unrelated recent scans — every type must be field-scoped.
    for (const type of cfg.supports) {
      const u = cfg.urlByType?.[type] ?? cfg.url;
      expect(u, type).toMatch(/q=page\.(domain|ip|url)%3A/);
    }
    // Verdicts are not present in the search API response, so none are mapped.
    expect(JSON.stringify(cfg.facts)).not.toContain('verdicts');
  });
});

describe('urlByType', () => {
  const vt = catalogEntry('virustotal')!;
  const row = { id: 'p1', name: 'VirusTotal', kind: 'virustotal', api_key: 'K', config: JSON.stringify(vt.config) };

  it('parseConfig preserves per-type URLs', () => {
    expect(parseConfig(JSON.stringify(vt.config)).urlByType?.domain).toContain('/domains/');
  });

  it('selects the per-type URL, falling back to url', () => {
    const cfg = parseConfig(JSON.stringify(vt.config));
    expect(cfg.urlByType?.['sha256']).toContain('/files/');
    expect(cfg.urlByType?.['ipv4']).toContain('/ip_addresses/');
    // A type with no override falls back to the generic template.
    const fallback = parseConfig(JSON.stringify({ supports: ['ipv4'], url: 'https://x/{value}', urlByType: { domain: 'https://y/{value}' } }));
    expect(fallback.urlByType?.['ipv4']).toBeUndefined();
    expect(fallback.url).toBe('https://x/{value}');
  });

  it('still renders the legacy {vt_path} template for pre-existing rows', () => {
    expect(render(vt.config.url, { value: '8.8.8.8', apiKey: 'K', type: 'ipv4' }))
      .toBe('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8');
    expect(providerFromRow(row).supports('domain')).toBe(true);
  });
});
