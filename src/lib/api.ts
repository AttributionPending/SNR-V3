import type { AnalysisResult, Session, ThreatActorSummary } from '../types';

const BASE = '/api';

/**
 * Authenticated fetch wrapper — injects Authorization + X-Team-Id headers.
 * Falls back to regular fetch if no token is stored.
 */
export async function authFetch(url: string, init?: RequestInit): Promise<Response> {
  const token = localStorage.getItem('snr_token');
  const teamId = localStorage.getItem('snr_active_team');
  const headers = new Headers(init?.headers);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (teamId) headers.set('X-Team-Id', teamId);

  const res = await fetch(url, { ...init, headers });

  // If 401 and we have a refresh token, try to refresh
  if (res.status === 401 && token) {
    const refreshToken = localStorage.getItem('snr_refresh_token');
    if (refreshToken) {
      const refreshRes = await fetch(`${BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken }),
      });
      if (refreshRes.ok) {
        const data = await refreshRes.json() as { token: string; refreshToken: string };
        localStorage.setItem('snr_token', data.token);
        localStorage.setItem('snr_refresh_token', data.refreshToken);
        headers.set('Authorization', `Bearer ${data.token}`);
        return fetch(url, { ...init, headers });
      } else {
        // Refresh failed — clear tokens, redirect to login
        localStorage.removeItem('snr_token');
        localStorage.removeItem('snr_refresh_token');
        localStorage.removeItem('snr_active_team');
        window.location.reload();
      }
    }
  }

  return res;
}

export async function fetchSessions(filters?: {
  search?: string;
  severity?: string;
  audience?: string;
  tags?: string;
}): Promise<Session[]> {
  const params = new URLSearchParams();
  if (filters?.search) params.set('search', filters.search);
  if (filters?.severity) params.set('severity', filters.severity);
  if (filters?.audience) params.set('audience', filters.audience);
  if (filters?.tags) params.set('tags', filters.tags);
  const qs = params.toString();
  const res = await authFetch(`${BASE}/sessions${qs ? `?${qs}` : ''}`);
  if (!res.ok) throw new Error('Failed to load sessions');
  const data = await res.json() as { sessions: Array<Session & { tags?: string | string[] }> };
  // Backend stores tags as JSON string — parse if needed
  return data.sessions.map((s) => ({
    ...s,
    tags: typeof s.tags === 'string' ? JSON.parse(s.tags || '[]') : (s.tags ?? []),
  }));
}

export async function fetchAllSessions(
  limit = 100,
  offset = 0,
  filters?: { search?: string; severity?: string; audience?: string; tags?: string },
): Promise<{ sessions: Session[]; total: number }> {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (filters?.search) params.set('search', filters.search);
  if (filters?.severity) params.set('severity', filters.severity);
  if (filters?.audience) params.set('audience', filters.audience);
  if (filters?.tags) params.set('tags', filters.tags);
  const res = await authFetch(`${BASE}/sessions?${params.toString()}`);
  if (!res.ok) throw new Error('Failed to load sessions');
  const data = await res.json() as { sessions: Array<Session & { tags?: string | string[] }>; total: number };
  const sessions = data.sessions.map((s) => ({
    ...s,
    tags: typeof s.tags === 'string' ? JSON.parse(s.tags || '[]') : (s.tags ?? []),
  })) as Session[];
  return { sessions, total: data.total };
}

export interface AuditLogEntry {
  id: number;
  timestamp: number;
  analyst_name: string;
  session_id: string | null;
  action: string;
  input_hash: string | null;
  outputs_generated: string | null;
  techniques_identified: string | null;
  details: string | null;
}

export interface TechniqueSession {
  id: string;
  name: string;
  severity: string | null;
  created_at: number;
}

export interface TechniqueEntry {
  technique_id: string;
  technique_name: string;
  tactic: string;
  sessions: TechniqueSession[];
}

export interface AnalyticsData {
  sessionsOverTime: { date: string; count: number }[];
  severityDistribution: { severity: string; count: number }[];
  audienceBreakdown: { audience: string; count: number }[];
  exportActivity: { export_type: string; count: number }[];
  iocDistribution: { ioc_type: string; count: number }[];
  techniqueMap: TechniqueEntry[];
}

export async function fetchAnalytics(days: number): Promise<AnalyticsData> {
  const res = await authFetch(`${BASE}/analytics?days=${days}`);
  if (!res.ok) throw new Error('Failed to load analytics');
  return res.json() as Promise<AnalyticsData>;
}

// ── Cross-session IOC correlation ────────────────────────────────────────────

export interface IocActorHint { id: string; name: string; shared: number }
export interface IocCorrelations {
  correlations: Record<string, { others: number; actors: IocActorHint[] }>;
  suggestedActors: { id: string; name: string; indicators: number }[];
}

/** Per-IOC "seen in N other incidents" data + actor suggestions for a session. */
export async function fetchIocCorrelations(sessionId: string): Promise<IocCorrelations> {
  const res = await authFetch(`${BASE}/sessions/${sessionId}/ioc-correlations`);
  if (!res.ok) throw new Error('Failed to load IOC correlations');
  return res.json() as Promise<IocCorrelations>;
}

export interface IocIndicator { type: string; value: string; norm: string; sessionCount: number; lastSeen: number; manual?: boolean; source?: string | null }

/** Browse distinct indicators across the team with incident counts. */
export async function listIocs(q = '', type = '', limit = 50, order: 'count' | 'recent' = 'count'): Promise<IocIndicator[]> {
  const qs = new URLSearchParams();
  if (q) qs.set('q', q);
  if (type) qs.set('type', type);
  qs.set('limit', String(limit));
  if (order === 'recent') qs.set('order', 'recent');
  const res = await authFetch(`${BASE}/iocs?${qs.toString()}`);
  if (!res.ok) throw new Error('Failed to load indicators');
  const data = await res.json() as { indicators: IocIndicator[] };
  return data.indicators;
}

export interface NewManualIoc { type: string; value: string; context?: string; confidence?: string; source?: string }

/** Add a manual (curated) indicator that is not tied to any report. */
export async function createManualIoc(ioc: NewManualIoc): Promise<void> {
  const res = await authFetch(`${BASE}/iocs`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(ioc) });
  if (!res.ok) {
    const msg = await res.json().catch(() => ({})) as { error?: string };
    throw new Error(msg.error || 'Failed to add indicator');
  }
}

/** Remove a manual indicator (by type + value). */
export async function deleteManualIoc(type: string, value: string): Promise<void> {
  const qs = new URLSearchParams({ type, value });
  const res = await authFetch(`${BASE}/iocs/manual?${qs.toString()}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to remove indicator');
}

// ── Indicator enrichment (pluggable external providers; none enabled by default) ─
export type EnrichmentStatus = 'ok' | 'not_found' | 'unconfigured' | 'unsupported' | 'error';
export interface EnrichmentFact { label: string; value: string; tone?: 'neutral' | 'good' | 'warn' | 'bad' }
export interface EnrichmentResult {
  providerId: string; providerName: string; status: EnrichmentStatus;
  summary?: string; facts?: EnrichmentFact[]; link?: string; message?: string; fetchedAt?: number;
}
export interface EnrichmentResponse {
  type: string; value: string;
  providers: EnrichmentResult[];
  anyRegistered: boolean;
  registered: { id: string; name: string; requiredSettings: string[] }[];
}

/** Run the configured enrichment providers against one indicator. */
export async function fetchEnrichment(type: string, value: string): Promise<EnrichmentResponse> {
  const qs = new URLSearchParams({ type, value });
  const res = await authFetch(`${BASE}/enrichment?${qs.toString()}`);
  if (!res.ok) throw new Error('Failed to load enrichment');
  return res.json() as Promise<EnrichmentResponse>;
}

// ── Enrichment provider administration (admin / team lead) ───────────────────
export interface EnrichmentFactSpec { label: string; path: string; tone?: 'neutral' | 'good' | 'warn' | 'bad' }
export interface EnrichmentProviderConfig {
  supports: string[];
  url: string;
  headers?: Record<string, string>;
  summary?: string;
  facts?: EnrichmentFactSpec[];
  link?: string;
  notFound?: number[];
}
export interface EnrichmentCatalogEntry {
  kind: string; name: string; keyLabel: string; docsUrl?: string; config: EnrichmentProviderConfig;
}
export interface EnrichmentProviderRecord {
  id: string; name: string; kind: string; enabled: number;
  config: string; has_key: boolean;
  last_status: string | null; last_used_at: number | null;
  created_at: number; updated_at: number;
}
export interface EnrichmentProviderInput {
  name?: string; kind?: string; apiKey?: string; config?: EnrichmentProviderConfig; enabled?: boolean;
}

const jsonBody = (url: string, method: string, body: unknown) =>
  authFetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const orThrow = async (res: Response, fallback: string) => {
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || fallback);
};

export async function fetchEnrichmentCatalog(): Promise<EnrichmentCatalogEntry[]> {
  const res = await authFetch(`${BASE}/enrichment/catalog`);
  if (!res.ok) throw new Error('Failed to load provider catalog');
  return (await res.json() as { catalog: EnrichmentCatalogEntry[] }).catalog;
}
export async function listEnrichmentProviders(): Promise<EnrichmentProviderRecord[]> {
  const res = await authFetch(`${BASE}/enrichment/providers`);
  if (!res.ok) throw new Error('Failed to load providers');
  return (await res.json() as { providers: EnrichmentProviderRecord[] }).providers;
}
export async function createEnrichmentProvider(input: EnrichmentProviderInput): Promise<void> {
  await orThrow(await jsonBody(`${BASE}/enrichment/providers`, 'POST', input), 'Failed to add provider');
}
export async function updateEnrichmentProvider(id: string, input: EnrichmentProviderInput): Promise<void> {
  await orThrow(await jsonBody(`${BASE}/enrichment/providers/${id}`, 'PATCH', input), 'Failed to update provider');
}
export async function deleteEnrichmentProvider(id: string): Promise<void> {
  const res = await authFetch(`${BASE}/enrichment/providers/${id}`, { method: 'DELETE' });
  await orThrow(res, 'Failed to delete provider');
}
export async function testEnrichmentProvider(id: string, type: string, value: string): Promise<EnrichmentResult> {
  const res = await jsonBody(`${BASE}/enrichment/providers/${id}/test`, 'POST', { type, value });
  await orThrow(res, 'Test failed');
  return (await res.json() as { result: EnrichmentResult }).result;
}

export interface IocManualProvenance { context: string; confidence: string | null; source: string; authorName: string; createdAt: number }

export interface IocOccurrences {
  type: string;
  value: string;
  sessions: { id: string; name: string; severity: string | null; createdAt: number }[];
  actors: { id: string; name: string }[];
  manual: IocManualProvenance | null;
}

/** Every incident (and attributed actor) sharing one indicator. */
export async function fetchIocOccurrences(type: string, value: string): Promise<IocOccurrences> {
  const qs = new URLSearchParams({ type, value });
  const res = await authFetch(`${BASE}/iocs/occurrences?${qs.toString()}`);
  if (!res.ok) throw new Error('Failed to load indicator occurrences');
  return res.json() as Promise<IocOccurrences>;
}

// ── Cases (investigations) + link-analysis graph ─────────────────────────────

export type CaseStatus = 'open' | 'monitoring' | 'closed';
export type CasePriority = 'critical' | 'high' | 'medium' | 'low';

export interface CaseSummary {
  id: string; name: string; summary: string; status: CaseStatus; priority: CasePriority;
  assignee: string | null; session_count: number; created_at: number; updated_at: number;
}
export interface CaseLinkedSession { id: string; name: string; severity: string | null; audience: string | null; created_at: number; added_at: number }
export interface CaseAggTTP { technique_id: string; technique_name: string; tactic: string; session_count: number; pinned?: boolean }
export interface CaseAggIOC { type: string; value: string; norm: string; session_count: number; first_seen: number | null; last_seen: number | null; any_false_positive?: boolean; pinned?: boolean; context?: string }
export interface CaseActor { id: string; name: string; session_count: number; pinned?: boolean }
export interface CaseLogEntry { id: string; user_id: string | null; author_name: string; entry_type: string; content: string; created_at: number }
export interface CaseDetail {
  case: CaseSummary;
  sessions: CaseLinkedSession[];
  aggregated_ttps: CaseAggTTP[];
  aggregated_iocs: CaseAggIOC[];
  actors: CaseActor[];
  log: CaseLogEntry[];
}

export interface GraphNode { id: string; type: 'case' | 'session' | 'actor' | 'ioc' | 'malware' | 'technique'; label: string; meta?: Record<string, string | number | null> }
export interface GraphData { nodes: GraphNode[]; edges: { source: string; target: string; label: string }[] }

export async function fetchCases(search = ''): Promise<{ cases: CaseSummary[]; total: number }> {
  const qs = search ? `?search=${encodeURIComponent(search)}` : '';
  const res = await authFetch(`${BASE}/cases${qs}`);
  if (!res.ok) throw new Error('Failed to load cases');
  return res.json() as Promise<{ cases: CaseSummary[]; total: number }>;
}
export async function fetchCaseDetail(id: string): Promise<CaseDetail> {
  const res = await authFetch(`${BASE}/cases/${id}`);
  if (!res.ok) throw new Error('Failed to load case');
  return res.json() as Promise<CaseDetail>;
}
export async function createCase(data: { name: string; summary?: string; priority?: CasePriority; sessionId?: string }): Promise<{ case: CaseSummary }> {
  const res = await authFetch(`${BASE}/cases`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed to create case');
  return res.json() as Promise<{ case: CaseSummary }>;
}
export async function updateCase(id: string, data: Partial<Pick<CaseSummary, 'name' | 'summary' | 'status' | 'priority' | 'assignee'>>): Promise<void> {
  const res = await authFetch(`${BASE}/cases/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
  if (!res.ok) throw new Error('Failed to update case');
}
export async function deleteCase(id: string): Promise<void> {
  const res = await authFetch(`${BASE}/cases/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to delete case');
}
export async function addCaseLog(id: string, content: string): Promise<void> {
  const res = await authFetch(`${BASE}/cases/${id}/log`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content }) });
  if (!res.ok) throw new Error('Failed to add log entry');
}
export async function linkCaseSessions(id: string, sessionIds: string[]): Promise<{ added: number }> {
  const res = await authFetch(`${BASE}/cases/${id}/sessions`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ session_ids: sessionIds }) });
  if (!res.ok) throw new Error('Failed to link sessions');
  return res.json() as Promise<{ added: number }>;
}
export async function unlinkCaseSession(id: string, sessionId: string): Promise<void> {
  const res = await authFetch(`${BASE}/cases/${id}/sessions/${sessionId}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to unlink session');
}
export async function fetchCaseAvailableSessions(id: string, search = ''): Promise<Array<{ id: string; name: string; severity: string | null; audience: string | null; created_at: number }>> {
  const qs = search ? `?search=${encodeURIComponent(search)}` : '';
  const res = await authFetch(`${BASE}/cases/${id}/sessions/available${qs}`);
  if (!res.ok) throw new Error('Failed to load available sessions');
  const data = await res.json() as { sessions: Array<{ id: string; name: string; severity: string | null; audience: string | null; created_at: number }> };
  return data.sessions;
}
export async function fetchCaseGraph(id: string): Promise<GraphData> {
  const res = await authFetch(`${BASE}/cases/${id}/graph`);
  if (!res.ok) throw new Error('Failed to load case graph');
  return res.json() as Promise<GraphData>;
}

// ── Pinned case members (actors / techniques / indicators) ────────────────────
const jsonPost = (url: string, body: unknown) => authFetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

export async function pinCaseActor(id: string, ref: { actor_id?: string; name?: string }): Promise<void> {
  const res = await jsonPost(`${BASE}/cases/${id}/actors`, ref);
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed to add actor');
}
export async function unpinCaseActor(id: string, actorId: string): Promise<void> {
  const res = await authFetch(`${BASE}/cases/${id}/actors/${actorId}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to remove actor');
}
export async function fetchCaseAvailableActors(id: string, search = ''): Promise<Array<{ id: string; name: string }>> {
  const qs = search ? `?search=${encodeURIComponent(search)}` : '';
  const res = await authFetch(`${BASE}/cases/${id}/actors/available${qs}`);
  if (!res.ok) throw new Error('Failed to load actors');
  return (await res.json() as { actors: Array<{ id: string; name: string }> }).actors;
}
export async function pinCaseTechnique(id: string, t: { technique_id: string; technique_name: string; tactic: string }): Promise<void> {
  const res = await jsonPost(`${BASE}/cases/${id}/techniques`, t);
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed to add technique');
}
export async function unpinCaseTechnique(id: string, techniqueId: string): Promise<void> {
  const res = await authFetch(`${BASE}/cases/${id}/techniques/${encodeURIComponent(techniqueId)}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to remove technique');
}
export async function pinCaseIoc(id: string, ioc: { type: string; value: string; context?: string }): Promise<void> {
  const res = await jsonPost(`${BASE}/cases/${id}/iocs`, ioc);
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed to add indicator');
}
export async function unpinCaseIoc(id: string, type: string, value: string): Promise<void> {
  const qs = new URLSearchParams({ type, value });
  const res = await authFetch(`${BASE}/cases/${id}/iocs?${qs.toString()}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to remove indicator');
}
export async function fetchGraph(seed: string): Promise<GraphData> {
  const res = await authFetch(`${BASE}/graph?seed=${encodeURIComponent(seed)}`);
  if (!res.ok) throw new Error('Failed to load graph');
  return res.json() as Promise<GraphData>;
}

// ── Intelligence holdings overview ────────────────────────────────────────────

export interface IntelActor { id: string; name: string; session_count: number; attribution_confidence: string | null }
export interface IntelTechnique { technique_id: string; technique_name: string; tactic: string; session_count: number }
export interface IntelSession { id: string; name: string; severity: string | null; created_at: number }

export interface IntelOverview {
  counts: { indicators: number; actors: number; techniques: number; incidents: number; cases: number };
  top_iocs: IocIndicator[];
  recent_iocs: IocIndicator[];
  top_actors: IntelActor[];
  top_techniques: IntelTechnique[];
  recent_sessions: IntelSession[];
}

export async function fetchIntelOverview(): Promise<IntelOverview> {
  const res = await authFetch(`${BASE}/intel/overview`);
  if (!res.ok) throw new Error('Failed to load intelligence overview');
  return res.json() as Promise<IntelOverview>;
}

// Paginated, sortable holdings for a single dashboard panel.
export type HoldingKind = 'indicators' | 'actors' | 'techniques' | 'sessions';
export interface HoldingItemMap {
  indicators: IocIndicator;
  actors: IntelActor;
  techniques: IntelTechnique;
  sessions: IntelSession;
}
export async function fetchHoldings<K extends HoldingKind>(
  kind: K, order: string, limit = 20, offset = 0,
): Promise<{ items: HoldingItemMap[K][]; hasMore: boolean }> {
  const qs = new URLSearchParams({ kind, order, limit: String(limit), offset: String(offset) });
  const res = await authFetch(`${BASE}/intel/holdings?${qs.toString()}`);
  if (!res.ok) throw new Error('Failed to load holdings');
  return res.json() as Promise<{ items: HoldingItemMap[K][]; hasMore: boolean }>;
}

// ── Entity annotations (comments on IOCs / threat actors) ─────────────────────

export type EntityRef =
  | { entity_type: 'ioc'; ioc_type: string; ioc_value: string; label?: string }
  | { entity_type: 'actor'; actor_id: string; label?: string };

export interface EntityAnnotation {
  id: string; entity_type: 'ioc' | 'actor'; entity_key: string; entity_label: string;
  user_id: string | null; author_name: string; content: string; created_at: number; updated_at: number;
}

function entityQuery(ref: EntityRef): string {
  const p = new URLSearchParams({ entity_type: ref.entity_type });
  if (ref.entity_type === 'ioc') { p.set('ioc_type', ref.ioc_type); p.set('ioc_value', ref.ioc_value); }
  else p.set('actor_id', ref.actor_id);
  return p.toString();
}

export async function listEntityAnnotations(ref: EntityRef): Promise<EntityAnnotation[]> {
  const res = await authFetch(`${BASE}/annotations?${entityQuery(ref)}`);
  if (!res.ok) throw new Error('Failed to load annotations');
  const data = await res.json() as { annotations: EntityAnnotation[] };
  return data.annotations;
}
export async function addEntityAnnotation(ref: EntityRef, content: string): Promise<EntityAnnotation> {
  const res = await authFetch(`${BASE}/annotations`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...ref, content }) });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed to add annotation');
  const data = await res.json() as { annotation: EntityAnnotation };
  return data.annotation;
}
export async function updateEntityAnnotation(id: string, content: string): Promise<void> {
  const res = await authFetch(`${BASE}/annotations/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content }) });
  if (!res.ok) throw new Error('Failed to update annotation');
}
export async function deleteEntityAnnotation(id: string): Promise<void> {
  const res = await authFetch(`${BASE}/annotations/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to delete annotation');
}
/** Batch annotation counts, returned aligned to the input `entities` order. */
export async function fetchAnnotationCounts(entities: EntityRef[]): Promise<number[]> {
  if (entities.length === 0) return [];
  const res = await authFetch(`${BASE}/annotations/counts`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ entities }) });
  if (!res.ok) return entities.map(() => 0);
  const data = await res.json() as { counts: number[] };
  return data.counts;
}

export async function fetchAuditLog(): Promise<AuditLogEntry[]> {
  const res = await authFetch(`${BASE}/sessions/audit/log`);
  if (!res.ok) throw new Error('Failed to load audit log');
  const data = await res.json() as { rows: AuditLogEntry[] };
  return data.rows;
}

export async function fetchSession(id: string): Promise<{
  session: Session;
  result: AnalysisResult | null;
  analystOverrides: Record<string, string>;
  inputs: Array<{ input_type: string; content: string; filename?: string }>;
  note: string;
  linked_threat_actor: { id: string; name: string } | null;
}> {
  const res = await authFetch(`${BASE}/sessions/${id}`);
  if (!res.ok) throw new Error('Failed to load session');
  const data = await res.json();
  // Parse tags JSON string to array (backend stores as JSON string in SQLite)
  if (data.session) {
    const t = data.session.tags;
    data.session.tags = typeof t === 'string' ? JSON.parse(t || '[]') : (t ?? []);
  }
  return data;
}

export async function createSession(data: {
  name: string;
  incident_id?: string;
  audience: string;
  origin?: 'analysis' | 'workbench';
}): Promise<string> {
  const res = await authFetch(`${BASE}/sessions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to create session');
  const j = await res.json() as { id: string };
  return j.id;
}

/** AI-draft the stakeholder narrative from authored findings (Workbench assist). */
export async function assistBriefDraft(
  sessionId: string,
  result: AnalysisResult,
  audience?: string,
): Promise<AnalysisResult['email_content']> {
  const res = await authFetch(`${BASE}/sessions/${sessionId}/assist/brief`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ result, audience }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'AI draft failed');
  return (await res.json() as { email_content: AnalysisResult['email_content'] }).email_content;
}

/** AI-extract techniques/IOCs/rules/flow from freeform notes (Workbench assist). */
export async function assistExtract(sessionId: string, notes: string): Promise<Omit<AnalysisResult, 'email_content'>> {
  const res = await authFetch(`${BASE}/sessions/${sessionId}/assist/extract`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ notes }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'AI extract failed');
  return (await res.json() as { technical: Omit<AnalysisResult, 'email_content'> }).technical;
}

/** AI-generate detection rules for the current techniques (Workbench assist). */
export async function assistRules(sessionId: string, result: AnalysisResult): Promise<AnalysisResult['detection_rules']> {
  const res = await authFetch(`${BASE}/sessions/${sessionId}/assist/rules`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ result }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'AI rules failed');
  return (await res.json() as { detection_rules: AnalysisResult['detection_rules'] }).detection_rules;
}

/** Save an analyst-authored AnalysisResult (Workbench). Returns the new version. */
export async function saveSessionResult(
  sessionId: string,
  result: AnalysisResult,
  expectedVersion?: number,
): Promise<number> {
  const res = await authFetch(`${BASE}/sessions/${sessionId}/result`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ result, expectedVersion }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed to save report');
  return (await res.json() as { version: number }).version;
}

export async function saveNote(sessionId: string, content: string): Promise<void> {
  await authFetch(`${BASE}/sessions/${sessionId}/note`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content }),
  });
}

export async function updateSessionName(sessionId: string, name: string): Promise<void> {
  await authFetch(`${BASE}/sessions/${sessionId}/name`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  });
}

export async function saveOverrides(sessionId: string, overrides: Record<string, string>): Promise<void> {
  await authFetch(`${BASE}/sessions/${sessionId}/overrides`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ overrides }),
  });
}

export async function streamAnalysis(
  params: {
    session_id: string;
    siem_input?: string;
    text_input?: string;
    logFile?: File;
    audience: string;
    redacted_strings?: string[];
  },
  onChunk: (text: string) => void,
  onComplete: (result: AnalysisResult) => void,
  onError: (err: string) => void,
  onStatus?: (msg: string, phase: number) => void
): Promise<void> {
  const formData = new FormData();
  formData.append('session_id', params.session_id);
  formData.append('audience', params.audience);
  if (params.siem_input) formData.append('siem_input', params.siem_input);
  if (params.text_input) formData.append('text_input', params.text_input);
  if (params.logFile) formData.append('logFile', params.logFile);
  if (params.redacted_strings?.length) {
    formData.append('redacted_strings', JSON.stringify(params.redacted_strings));
  }

  const res = await authFetch(`${BASE}/analyze`, { method: 'POST', body: formData });
  if (!res.ok || !res.body) {
    onError(`HTTP ${res.status}`);
    return;
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';

    for (const line of lines) {
      if (line.startsWith('event: chunk')) continue;
      if (line.startsWith('data: ')) {
        const data = line.slice(6);
        try {
          const parsed = JSON.parse(data) as { text?: string; result?: AnalysisResult; error?: string; message?: string; phase?: number };
          if (parsed.text) onChunk(parsed.text);
          else if (parsed.result) onComplete(parsed.result);
          else if (parsed.error) onError(parsed.error);
          else if (parsed.message && onStatus) onStatus(parsed.message, parsed.phase ?? 1);
        } catch {
          // partial event, continue
        }
      }
    }
  }
}

/** Re-run analysis on an existing session using its stored inputs (SSE). */
export async function streamReanalysis(
  sessionId: string,
  audience: string | undefined,
  onChunk: (text: string) => void,
  onComplete: (result: AnalysisResult) => void,
  onError: (err: string) => void,
  onStatus?: (msg: string, phase: number) => void
): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/rerun/${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(audience ? { audience } : {}),
  });
  if (!res.ok || !res.body) {
    // Non-SSE failure (e.g. no stored inputs) returns JSON
    const d = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    onError(d.error || `HTTP ${res.status}`);
    return;
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';

    for (const line of lines) {
      if (line.startsWith('event: chunk')) continue;
      if (line.startsWith('data: ')) {
        const data = line.slice(6);
        try {
          const parsed = JSON.parse(data) as { text?: string; result?: AnalysisResult; error?: string; message?: string; phase?: number };
          if (parsed.text) onChunk(parsed.text);
          else if (parsed.result) onComplete(parsed.result);
          else if (parsed.error) onError(parsed.error);
          else if (parsed.message && onStatus) onStatus(parsed.message, parsed.phase ?? 1);
        } catch {
          // partial event, continue
        }
      }
    }
  }
}

export async function fetchEmailPreview(params: {
  showObservations?: boolean;
  showTechniques?: boolean;
  showAffectedAssets?: boolean;
  showActions?: boolean;
  showIocs?: boolean;
  showNextSteps?: boolean;
  audience?: string;
  tlp?: string;
}): Promise<string> {
  const qs = new URLSearchParams();
  if (params.showObservations   === false) qs.set('show_observations',    'false');
  if (params.showTechniques     === false) qs.set('show_techniques',      'false');
  if (params.showAffectedAssets === false) qs.set('show_affected_assets', 'false');
  if (params.showActions        === false) qs.set('show_actions',         'false');
  if (params.showIocs           === false) qs.set('show_iocs',            'false');
  if (params.showNextSteps      === false) qs.set('show_next_steps',      'false');
  if (params.audience) qs.set('audience', params.audience);
  if (params.tlp)      qs.set('tlp', params.tlp);
  const res = await authFetch(`${BASE}/analyze/email-preview?${qs.toString()}`);
  if (!res.ok) throw new Error('Failed to load email preview');
  return res.text();
}

/** Preview the email rendered through an in-progress (unsaved) body template. */
export async function fetchEmailTemplatePreview(params: {
  template: string;
  audience?: string;
  tlp?: string;
}): Promise<string> {
  const res = await authFetch(`${BASE}/analyze/email-preview`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ template: params.template, audience: params.audience ?? 'soc', tlp: params.tlp ?? 'AMBER' }),
  });
  if (!res.ok) throw new Error('Failed to load email preview');
  return res.text();
}

/** Render the REAL session email as HTML, applying in-progress (unsaved) edits. */
export async function fetchEmailStudioPreview(params: {
  session_id?: string;
  audience?: string;
  tlp?: string;
  template?: string;
  branding?: Record<string, string>;
  reportSections?: string;
  emailContentOverrides?: Record<string, string>;
  theme?: Partial<EmailThemeOverrides>;
  sender?: Partial<EmailSenderOverrides>;
}): Promise<string> {
  const res = await authFetch(`${BASE}/analyze/email-studio-preview`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed to load email preview');
  return res.text();
}

// ── Brand profiles (white-label themes + sender identity) ────────────────────

/** Visual theme overrides applied to a rendered email (all optional). */
export interface EmailThemeOverrides {
  primary: string;
  secondary: string;
  pageBg: string;
  bodyText: string;
  tableHeaderBg: string;
  tableHeaderText: string;
  headerTitle: string;
  headerSubtitle: string;
  footerText: string;
  showVendorAttribution: boolean;
  logoDataUri: string;
  logoAlt: string;
  logoLink: string;
  logoMaxWidth: number;
  logoMaxHeight: number;
  fontFamily: string;
  bodyFontSize: string;
  lang: string;
}

/** Sender identity overrides (From / Reply-To / CC / BCC / preheader / subject). */
export interface EmailSenderOverrides {
  fromName: string;
  fromEmail: string;
  replyTo: string;
  cc: string;
  bcc: string;
  preheader: string;
  subjectTemplate: string;
}

export interface BrandProfile {
  id: string;
  name: string;
  isDefault: boolean;
  theme: Partial<EmailThemeOverrides>;
  sender: Partial<EmailSenderOverrides>;
  createdAt: number;
  updatedAt: number;
}

export interface ResolvedBrand {
  profileId: string | null;
  name: string;
  theme: Partial<EmailThemeOverrides>;
  sender: Partial<EmailSenderOverrides>;
}

export async function listBrandProfiles(): Promise<BrandProfile[]> {
  const res = await authFetch(`${BASE}/brand-profiles`);
  if (!res.ok) throw new Error('Failed to load brand profiles');
  const data = await res.json() as { profiles: BrandProfile[] };
  return data.profiles;
}

export async function createBrandProfile(input: {
  name: string;
  theme?: Partial<EmailThemeOverrides>;
  sender?: Partial<EmailSenderOverrides>;
  isDefault?: boolean;
}): Promise<string> {
  const res = await authFetch(`${BASE}/brand-profiles`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed to create brand profile');
  return (await res.json() as { id: string }).id;
}

export async function updateBrandProfile(id: string, patch: {
  name?: string;
  theme?: Partial<EmailThemeOverrides>;
  sender?: Partial<EmailSenderOverrides>;
  isDefault?: boolean;
}): Promise<void> {
  const res = await authFetch(`${BASE}/brand-profiles/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(patch),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed to update brand profile');
}

export async function deleteBrandProfile(id: string): Promise<void> {
  const res = await authFetch(`${BASE}/brand-profiles/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed to delete brand profile');
}

export async function fetchSessionBrand(sessionId: string): Promise<ResolvedBrand> {
  const res = await authFetch(`${BASE}/brand-profiles/session/${sessionId}`);
  if (!res.ok) throw new Error('Failed to resolve session brand');
  return res.json() as Promise<ResolvedBrand>;
}

export async function setSessionBrandProfile(sessionId: string, profileId: string | null): Promise<void> {
  const res = await authFetch(`${BASE}/brand-profiles/session/${sessionId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ profileId }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed to set session brand');
}

export async function exportStix(sessionId: string, tlp: string): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/export/stix`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, tlp }),
  });
  if (!res.ok) throw new Error('STIX export failed');
  const blob = await res.blob();
  downloadBlob(blob, getFilenameFromResponse(res, 'stix.json'));
}

export async function exportNavigator(sessionId: string): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/export/navigator`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId }),
  });
  if (!res.ok) throw new Error('Navigator export failed');
  const blob = await res.blob();
  downloadBlob(blob, getFilenameFromResponse(res, 'navigator.json'));
}

export async function exportDetectionRules(sessionId: string, tlp: string): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/export/detection-rules`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, tlp }),
  });
  if (!res.ok) throw new Error('Detection rules export failed');
  const blob = await res.blob();
  downloadBlob(blob, getFilenameFromResponse(res, 'detection-rules.txt'));
}

export async function exportAttackFlow(sessionId: string): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/export/attack-flow`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId }),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Attack Flow export failed' }));
    throw new Error(d.error || 'Attack Flow export failed');
  }
  const blob = await res.blob();
  downloadBlob(blob, getFilenameFromResponse(res, 'attack-flow.afb'));
}

export async function exportIocsCsv(sessionId: string, tlp: string): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/export/iocs-csv`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, tlp }),
  });
  if (!res.ok) throw new Error('IOC CSV export failed');
  const blob = await res.blob();
  downloadBlob(blob, getFilenameFromResponse(res, 'iocs.csv'));
}

export async function deleteSession(id: string): Promise<void> {
  const res = await authFetch(`${BASE}/sessions/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to delete session');
}

/** Undo a soft delete — sessions are recoverable for 7 days after deletion. */
export async function restoreSession(id: string): Promise<void> {
  const res = await authFetch(`${BASE}/sessions/${id}/restore`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to restore session');
}

/** List soft-deleted sessions still within the 7-day retention window. */
export async function fetchDeletedSessions(): Promise<Array<Session & { deleted_at: number }>> {
  const res = await authFetch(`${BASE}/sessions/deleted`);
  if (!res.ok) throw new Error('Failed to load deleted sessions');
  const data = await res.json() as { sessions: Array<Session & { deleted_at: number }> };
  return data.sessions;
}

export async function bulkDeleteSessions(sessionIds: string[]): Promise<{ deleted: number; errors: string[] }> {
  const res = await authFetch(`${BASE}/sessions/bulk-delete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_ids: sessionIds }),
  });
  if (!res.ok) throw new Error('Failed to bulk delete sessions');
  return res.json();
}

export async function exportEml(params: {
  session_id: string;
  audience: string;
  tlp: string;
  attach_stix?: boolean;
  attach_navigator?: boolean;
  attach_iocs?: boolean;
  attach_detection_rules?: boolean;
  diagram_jpg_b64?: string;
  email_content_overrides?: Partial<AnalysisResult['email_content']>;
}): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/export/eml`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw new Error(`Email export failed: ${errText || res.statusText}`);
  }
  const blob = await res.blob();
  downloadBlob(blob, getFilenameFromResponse(res, 'brief.eml'));
}

export async function fetchReportPreview(params: {
  session_id: string;
  audience: string;
  tlp: string;
  email_content_overrides?: Partial<AnalysisResult['email_content']>;
}): Promise<string> {
  const res = await authFetch(`${BASE}/analyze/report-preview`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) throw new Error('Failed to load report preview');
  return res.text();
}

export async function exportReport(params: {
  session_id: string;
  audience: string;
  tlp: string;
  email_content_overrides?: Partial<AnalysisResult['email_content']>;
}): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/export/report`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) throw new Error('Report export failed');
  const blob = await res.blob();
  downloadBlob(blob, getFilenameFromResponse(res, 'cti-report.md'));
}

export async function fetchSettings(): Promise<Record<string, string>> {
  const res = await authFetch(`${BASE}/settings`);
  if (!res.ok) throw new Error('Failed to load settings');
  const data = await res.json() as { settings: Record<string, string> };
  return data.settings;
}

export async function saveSettings(updates: Record<string, string>): Promise<void> {
  await authFetch(`${BASE}/settings`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates),
  });
}

export async function uploadLogo(file: File): Promise<string> {
  const form = new FormData();
  form.append('logo', file);
  const res = await authFetch(`${BASE}/settings/logo`, { method: 'POST', body: form });
  if (!res.ok) throw new Error('Logo upload failed');
  const data = await res.json() as { dataUri: string };
  return data.dataUri;
}

export async function deleteLogo(): Promise<void> {
  await authFetch(`${BASE}/settings/logo`, { method: 'DELETE' });
}

export async function exportZip(params: {
  session_id: string;
  audience: string;
  tlp: string;
  attach_iocs?: boolean;
  diagram_jpg_b64?: string;
  email_content_overrides?: Partial<AnalysisResult['email_content']>;
}): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/export/zip`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) throw new Error('Zip export failed');
  const blob = await res.blob();
  downloadBlob(blob, getFilenameFromResponse(res, 'export.zip'));
}

// ── Auth API ──────────────────────────────────────────────────────────────────

export async function login(email: string, password: string): Promise<{
  token: string;
  refreshToken: string;
  user: { id: string; email: string; displayName: string; role: string };
  teams: Array<{ id: string; name: string; role: string }>;
}> {
  const res = await fetch(`${BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({ error: 'Login failed' }));
    throw new Error(data.error || 'Login failed');
  }
  return res.json();
}

export async function fetchMe(): Promise<{
  user: { id: string; email: string; displayName: string; role: string };
  teams: Array<{ id: string; name: string; role: string }>;
}> {
  const res = await authFetch(`${BASE}/auth/me`);
  if (!res.ok) throw new Error('Not authenticated');
  return res.json();
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  const res = await authFetch(`${BASE}/auth/me/password`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ currentPassword, newPassword }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({ error: 'Password change failed' }));
    throw new Error(data.error || 'Password change failed');
  }
}

// ── Users API (admin) ─────────────────────────────────────────────────────────

export async function fetchUsers(): Promise<Array<{
  id: string; email: string; displayName: string; role: string;
  createdAt: number; lastLoginAt: number | null; disabled: boolean;
  teams: Array<{ id: string; name: string; role: string }>;
}>> {
  const res = await authFetch(`${BASE}/users`);
  if (!res.ok) throw new Error('Failed to load users');
  return res.json();
}

export async function createUser(data: {
  email: string; password: string; displayName: string; role?: string;
}): Promise<{ id: string }> {
  const res = await authFetch(`${BASE}/users`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Failed to create user' }));
    throw new Error(d.error);
  }
  return res.json();
}

export async function updateUser(id: string, data: {
  displayName?: string; role?: string; disabled?: boolean;
}): Promise<void> {
  const res = await authFetch(`${BASE}/users/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Failed to update user' }));
    throw new Error(d.error);
  }
}

export async function resetUserPassword(id: string, newPassword: string): Promise<void> {
  const res = await authFetch(`${BASE}/users/${id}/password`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ newPassword }),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Password reset failed' }));
    throw new Error(d.error);
  }
}

export async function disableUser(id: string): Promise<void> {
  const res = await authFetch(`${BASE}/users/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to disable user');
}

// ── Teams API ─────────────────────────────────────────────────────────────────

export async function fetchTeams(): Promise<Array<{
  id: string; name: string; description: string; createdAt: number; memberCount: number;
}>> {
  const res = await authFetch(`${BASE}/teams`);
  if (!res.ok) throw new Error('Failed to load teams');
  return res.json();
}

export async function createTeam(data: { name: string; description?: string }): Promise<{ id: string }> {
  const res = await authFetch(`${BASE}/teams`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Failed to create team' }));
    throw new Error(d.error);
  }
  return res.json();
}

export async function fetchTeamDetail(id: string): Promise<{
  id: string; name: string; description: string;
  members: Array<{ userId: string; email: string; displayName: string; userRole: string; teamRole: string; joinedAt: number }>;
}> {
  const res = await authFetch(`${BASE}/teams/${id}`);
  if (!res.ok) throw new Error('Failed to load team');
  return res.json();
}

export async function updateTeam(id: string, data: { name?: string; description?: string }): Promise<void> {
  const res = await authFetch(`${BASE}/teams/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update team');
}

export async function deleteTeam(id: string): Promise<void> {
  const res = await authFetch(`${BASE}/teams/${id}`, { method: 'DELETE' });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Failed to delete team' }));
    throw new Error(d.error);
  }
}

export async function addTeamMember(teamId: string, userId: string, role?: string): Promise<void> {
  const res = await authFetch(`${BASE}/teams/${teamId}/members`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId, role: role || 'member' }),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Failed to add member' }));
    throw new Error(d.error);
  }
}

export async function updateTeamMemberRole(teamId: string, userId: string, role: string): Promise<void> {
  const res = await authFetch(`${BASE}/teams/${teamId}/members/${userId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role }),
  });
  if (!res.ok) throw new Error('Failed to update member role');
}

export async function removeTeamMember(teamId: string, userId: string): Promise<void> {
  const res = await authFetch(`${BASE}/teams/${teamId}/members/${userId}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to remove member');
}

// ── Threat Actors API ────────────────────────────────────────────────────────

export async function fetchThreatActors(filters?: { search?: string }): Promise<{
  actors: Array<{
    id: string; name: string; aliases: string[]; motivation: string | null;
    attribution_confidence: string | null; intrusion_set: string | null;
    campaign_name: string | null; malware_families: string[];
    description: string; session_count: number; latest_session_at: number | null;
    created_at: number;
  }>;
  total: number;
}> {
  const params = new URLSearchParams();
  if (filters?.search) params.set('search', filters.search);
  const qs = params.toString() ? `?${params.toString()}` : '';
  const res = await authFetch(`${BASE}/threat-actors${qs}`);
  if (!res.ok) throw new Error('Failed to load threat actors');
  return res.json();
}

export async function fetchThreatActorDetail(id: string): Promise<{
  actor: {
    id: string; name: string; aliases: string[]; motivation: string | null;
    attribution_confidence: string | null; intrusion_set: string | null;
    campaign_name: string | null; malware_families: string[];
    description: string; session_count: number; latest_session_at: number | null;
    created_at: number;
  };
  sessions: Array<{
    id: string; name: string; severity: string | null; audience: string | null;
    created_at: number; link_type: 'auto' | 'manual';
  }>;
  aggregated_ttps: Array<{
    technique_id: string; technique_name: string; tactic: string;
    session_count: number; sessions: Array<{ id: string; name: string }>;
  }>;
  aggregated_iocs: Array<{
    type: string; value: string; context: string; confidence: string;
    session_count: number; first_seen: number; last_seen: number;
  }>;
}> {
  const res = await authFetch(`${BASE}/threat-actors/${id}`);
  if (!res.ok) throw new Error('Failed to load threat actor details');
  return res.json();
}

export async function updateThreatActor(id: string, data: Record<string, unknown>): Promise<void> {
  const res = await authFetch(`${BASE}/threat-actors/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Update failed' }));
    throw new Error(d.error || 'Update failed');
  }
}

export async function linkSessionToActor(actorId: string, sessionId: string): Promise<void> {
  const res = await authFetch(`${BASE}/threat-actors/${actorId}/link`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId }),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Link failed' }));
    throw new Error(d.error || 'Link failed');
  }
}

export async function unlinkSessionFromActor(actorId: string, sessionId: string): Promise<void> {
  const res = await authFetch(`${BASE}/threat-actors/${actorId}/link/${sessionId}`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error('Unlink failed');
}

export async function mergeThreatActors(sourceId: string, targetId: string): Promise<void> {
  const res = await authFetch(`${BASE}/threat-actors/merge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source_id: sourceId, target_id: targetId }),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Merge failed' }));
    throw new Error(d.error || 'Merge failed');
  }
}

export async function deleteThreatActor(id: string): Promise<void> {
  const res = await authFetch(`${BASE}/threat-actors/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to delete threat actor');
}

export async function fetchAvailableSessions(actorId: string, search?: string): Promise<Array<{
  id: string; name: string; severity: string | null; audience: string | null; created_at: number;
}>> {
  const params = new URLSearchParams();
  if (search) params.set('search', search);
  const qs = params.toString() ? `?${params.toString()}` : '';
  const res = await authFetch(`${BASE}/threat-actors/${actorId}/sessions/available${qs}`);
  if (!res.ok) throw new Error('Failed to load available sessions');
  const data = await res.json() as { sessions: Array<{ id: string; name: string; severity: string | null; audience: string | null; created_at: number }> };
  return data.sessions;
}

// ── Tags ─────────────────────────────────────────────────────────────────────

export async function updateSessionTags(sessionId: string, tags: string[]): Promise<{ tags: string[] }> {
  const res = await authFetch(`${BASE}/sessions/${sessionId}/tags`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tags }),
  });
  if (!res.ok) throw new Error('Failed to update tags');
  return res.json();
}

export async function fetchAllTags(): Promise<string[]> {
  const res = await authFetch(`${BASE}/sessions/tags/all`);
  if (!res.ok) throw new Error('Failed to load tags');
  const data = await res.json() as { tags: string[] };
  return data.tags;
}

// ── Threat Actor Manual Management ──────────────────────────────────────────

export async function createThreatActor(data: {
  name: string;
  aliases?: string[];
  motivation?: string | null;
  attribution_confidence?: string | null;
  intrusion_set?: string | null;
  campaign_name?: string | null;
  malware_families?: string[];
  description?: string;
}): Promise<{ actor: ThreatActorSummary }> {
  const res = await authFetch(`${BASE}/threat-actors`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Failed to create threat actor' }));
    throw new Error(d.error || 'Failed to create threat actor');
  }
  return res.json();
}

export async function assignSessionThreatActor(
  sessionId: string,
  threatActorId: string | null,
): Promise<{ ok: boolean; threat_actor: { id: string; name: string } | null }> {
  const res = await authFetch(`${BASE}/sessions/${sessionId}/threat-actor`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ threat_actor_id: threatActorId }),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Failed to assign threat actor' }));
    throw new Error(d.error || 'Failed to assign threat actor');
  }
  return res.json();
}

export async function bulkLinkSessions(
  actorId: string,
  sessionIds: string[],
  removeExisting = false,
): Promise<{ ok: boolean; linked: number; skipped: number }> {
  const res = await authFetch(`${BASE}/threat-actors/${actorId}/link/bulk`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_ids: sessionIds, remove_existing: removeExisting }),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Bulk link failed' }));
    throw new Error(d.error || 'Bulk link failed');
  }
  return res.json();
}

export async function fetchUngroupedSessions(search?: string): Promise<Array<{
  id: string; name: string; severity: string | null; audience: string | null; created_at: number;
}>> {
  const params = new URLSearchParams();
  if (search) params.set('search', search);
  const qs = params.toString() ? `?${params.toString()}` : '';
  const res = await authFetch(`${BASE}/sessions/ungrouped${qs}`);
  if (!res.ok) throw new Error('Failed to load ungrouped sessions');
  const data = await res.json() as { sessions: Array<{ id: string; name: string; severity: string | null; audience: string | null; created_at: number }> };
  return data.sessions;
}

// ── Global Intelligence Search ───────────────────────────────────────────────

export interface SearchHit {
  category: 'ioc' | 'technique' | 'threat_actor' | 'session' | 'asset';
  value: string;
  context: string;
  session_id: string;
  session_name: string;
  meta?: Record<string, string>;
  /** For aggregated results — all sessions containing this hit */
  sessions?: Array<{ id: string; name: string }>;
}

export async function searchIntelligence(query: string, limit = 30): Promise<{
  results: SearchHit[];
  query: string;
  total: number;
}> {
  const params = new URLSearchParams({ q: query, limit: String(limit) });
  const res = await authFetch(`${BASE}/search?${params.toString()}`);
  if (!res.ok) throw new Error('Search failed');
  return res.json();
}

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function getFilenameFromResponse(res: Response, fallback: string): string {
  const cd = res.headers.get('content-disposition') ?? '';
  const match = cd.match(/filename="([^"]+)"/);
  return match?.[1] ?? fallback;
}

// ── API key management (admin) ───────────────────────────────────────────────

export interface ServiceAccountRecord {
  id: string;
  name: string;
  team_id: string;
  role: 'analyst' | 'viewer';
  disabled: number;
  active_keys: number;
  created_at: number;
}

export interface ApiKeyRecord {
  id: string;
  name: string;
  prefix: string;
  scopes: string;
  rate_limit_per_min: number;
  created_at: number;
  last_used_at: number | null;
  expires_at: number | null;
  revoked_at: number | null;
}

export async function getApiScopes(): Promise<string[]> {
  const res = await authFetch(`${BASE}/keys/scopes`);
  if (!res.ok) throw new Error('Failed to load scopes');
  return (await res.json()).scopes;
}

export async function listServiceAccounts(): Promise<ServiceAccountRecord[]> {
  const res = await authFetch(`${BASE}/keys/service-accounts`);
  if (!res.ok) throw new Error('Failed to load service accounts');
  return (await res.json()).serviceAccounts;
}

export async function createServiceAccount(name: string, role: 'analyst' | 'viewer'): Promise<{ id: string }> {
  const res = await authFetch(`${BASE}/keys/service-accounts`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, role }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed to create service account');
  return res.json();
}

export async function setServiceAccountDisabled(id: string, disabled: boolean): Promise<void> {
  const res = await authFetch(`${BASE}/keys/service-accounts/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ disabled }),
  });
  if (!res.ok) throw new Error('Failed to update service account');
}

export async function listApiKeys(accountId: string): Promise<ApiKeyRecord[]> {
  const res = await authFetch(`${BASE}/keys/service-accounts/${accountId}/keys`);
  if (!res.ok) throw new Error('Failed to load keys');
  return (await res.json()).keys;
}

export async function mintApiKey(
  accountId: string,
  body: { name: string; scopes: string[]; rateLimitPerMin?: number },
): Promise<{ id: string; token: string; prefix: string }> {
  const res = await authFetch(`${BASE}/keys/service-accounts/${accountId}/keys`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed to mint key');
  return res.json();
}

export async function revokeApiKey(keyId: string): Promise<void> {
  const res = await authFetch(`${BASE}/keys/${keyId}/revoke`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to revoke key');
}

// ── Threat-intel feeds (admin/lead) ──────────────────────────────────────────

export interface FeedRecord {
  id: string;
  name: string;
  type: 'taxii' | 'misp' | 'rss';
  url: string;
  audience: string;
  tags: string;
  cadence_minutes: number;
  max_items: number;
  enabled: number;
  last_polled_at: number | null;
  last_status: string | null;
  has_auth?: boolean;
}

export interface FeedInput {
  name: string;
  type: 'taxii' | 'misp' | 'rss';
  url: string;
  authToken?: string;
  config?: string;
  audience?: string;
  tags?: string[];
  cadenceMinutes?: number;
  maxItems?: number;
}

export async function listFeeds(): Promise<FeedRecord[]> {
  const res = await authFetch(`${BASE}/feeds`);
  if (!res.ok) throw new Error('Failed to load feeds');
  return (await res.json()).feeds;
}

export async function createFeed(body: FeedInput): Promise<{ id: string }> {
  const res = await authFetch(`${BASE}/feeds`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed to create feed');
  return res.json();
}

export async function updateFeed(id: string, body: Partial<FeedInput> & { enabled?: boolean }): Promise<void> {
  const res = await authFetch(`${BASE}/feeds/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error('Failed to update feed');
}

export async function deleteFeed(id: string): Promise<void> {
  const res = await authFetch(`${BASE}/feeds/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to delete feed');
}

export async function testFeed(id: string): Promise<{ count: number; sample: string[] }> {
  const res = await authFetch(`${BASE}/feeds/${id}/test`, { method: 'POST' });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Feed test failed');
  return res.json();
}

export async function pollFeedNow(id: string): Promise<{ fetched: number; ingested: number; skipped: number }> {
  const res = await authFetch(`${BASE}/feeds/${id}/poll`, { method: 'POST' });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Feed poll failed');
  return res.json();
}

// ── Detection-as-code publishing ─────────────────────────────────────────────

export async function getPublishStatus(): Promise<{ configured: boolean; repo: string | null; branch: string | null }> {
  const res = await authFetch(`${BASE}/publish/status`);
  if (!res.ok) throw new Error('Failed to load publish status');
  return res.json();
}

export async function publishDetections(sessionId: string): Promise<{ prUrl: string; prNumber: number; files: string[]; updated: boolean }> {
  const res = await authFetch(`${BASE}/publish/${sessionId}`, { method: 'POST' });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Publish failed');
  return res.json();
}
