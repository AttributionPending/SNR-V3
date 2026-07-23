/**
 * Shared types for indicator enrichment providers.
 *
 * An enrichment provider answers "what does an external source know about this
 * indicator?" (reputation, first/last seen, categories, a pivot link). Providers
 * are deliberately pluggable and OFF by default: none ship enabled, so no
 * indicator value leaves the network until an operator configures one. Adding a
 * provider (VirusTotal, AbuseIPDB, Shodan, …) means implementing
 * `EnrichmentProvider` and registering it in ./index.ts — the API surface and the
 * indicator card render it without further change.
 *
 * Mirrors the connector conventions in ../feeds/types.ts.
 */

/** Indicator kinds a provider may support (matches ioc_observations.ioc_type). */
export type IocType = string;

export interface EnrichmentRequest {
  type: IocType;
  /** Refanged, normalized indicator value. */
  value: string;
  teamId: string;
  /** Per-team settings (already resolved), e.g. { virustotal_api_key: '…' }. */
  settings: Record<string, string>;
}

/** One labelled fact rendered as a row in the provider card. */
export interface EnrichmentFact {
  label: string;
  value: string;
  /** Optional severity hint driving the value's colour in the UI. */
  tone?: 'neutral' | 'good' | 'warn' | 'bad';
}

export type EnrichmentStatus =
  | 'ok'            // provider ran and returned data
  | 'not_found'     // provider ran; nothing known about this indicator
  | 'unconfigured'  // provider is registered but missing credentials/settings
  | 'unsupported'   // provider does not handle this indicator type
  | 'error';        // provider failed (network, quota, bad response)

export interface EnrichmentResult {
  /** Stable provider id, e.g. 'virustotal'. */
  providerId: string;
  /** Display name, e.g. 'VirusTotal'. */
  providerName: string;
  status: EnrichmentStatus;
  /** One-line headline, e.g. '7/94 engines flagged this'. */
  summary?: string;
  /** Detail rows shown under the headline. */
  facts?: EnrichmentFact[];
  /** Deep link to the provider's own page for this indicator. */
  link?: string;
  /** Human-readable reason when status is 'error' / 'unconfigured'. */
  message?: string;
  /** Epoch ms the data was produced (or served from cache). */
  fetchedAt?: number;
}

export interface EnrichmentProvider {
  id: string;
  name: string;
  /** Indicator types this provider can enrich. */
  supports(type: IocType): boolean;
  /** True when the provider has everything it needs to run (API key, etc.). */
  isConfigured(settings: Record<string, string>): boolean;
  /** Settings keys an operator must supply — surfaced in the UI's empty state. */
  requiredSettings: string[];
  /** Perform the lookup. Must not throw; return a status:'error' result instead. */
  enrich(req: EnrichmentRequest): Promise<EnrichmentResult>;
}
