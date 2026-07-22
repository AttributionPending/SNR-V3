/**
 * Route integration tests (supertest against the exported Express app). Runs only
 * when TEST_DATABASE_URL is set (CI provides Postgres); otherwise skipped so
 * `npm test` stays green locally. Covers the Workbench PUT /result, brand-profile
 * governance, and the delete → deleted → restore flow — no LLM calls involved.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';

const TEST_DB = process.env.TEST_DATABASE_URL;
const suite = TEST_DB ? describe : describe.skip;

suite('sessions + brand-profiles routes', () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let app: any; let client: any;
  let adminToken = ''; let viewerToken = '';
  const TEAM = 'it_team';
  const auth = (t: string) => ({ Authorization: `Bearer ${t}`, 'X-Team-Id': TEAM });

  beforeAll(async () => {
    process.env.DATABASE_URL = TEST_DB;
    process.env.JWT_SECRET = 'integration-test-secret';
    process.env.SNR_SKIP_LISTEN = '1';
    process.env.NODE_ENV = 'test';

    client = await import('../../server/db/client.js');
    const { runMigrations } = await import('../../server/db/migrate.js');
    await runMigrations();

    const now = Date.now();
    await client.rawQuery("INSERT INTO teams (id,name,created_at,updated_at) VALUES ($1,'IT',$2,$2) ON CONFLICT (id) DO NOTHING", [TEAM, now]);
    await client.rawQuery("INSERT INTO users (id,email,password_hash,display_name,role,created_at,updated_at) VALUES ('it_admin','admin@it','x','Admin','admin',$1,$1) ON CONFLICT (id) DO NOTHING", [now]);
    await client.rawQuery("INSERT INTO users (id,email,password_hash,display_name,role,created_at,updated_at) VALUES ('it_viewer','viewer@it','x','Viewer','viewer',$1,$1) ON CONFLICT (id) DO NOTHING", [now]);
    await client.rawQuery("INSERT INTO team_members (team_id,user_id,role,joined_at) VALUES ($1,'it_admin','lead',$2) ON CONFLICT DO NOTHING", [TEAM, now]);
    await client.rawQuery("INSERT INTO team_members (team_id,user_id,role,joined_at) VALUES ($1,'it_viewer','member',$2) ON CONFLICT DO NOTHING", [TEAM, now]);

    const authUtils = await import('../../server/lib/auth-utils.js');
    if ('initAuthSecret' in authUtils) await (authUtils as { initAuthSecret: () => Promise<void> }).initAuthSecret();
    adminToken = authUtils.signAccessToken({ id: 'it_admin', email: 'admin@it', role: 'admin' });
    viewerToken = authUtils.signAccessToken({ id: 'it_viewer', email: 'viewer@it', role: 'viewer' });

    app = (await import('../../server/index.js')).default;
  });

  afterAll(async () => { if (client) await client.closeDb(); });

  const minimalResult = (title = 'Authored') => ({
    incident_summary: { title, severity: 'High', confidence: 'High', description: 'd', analyst_notes: '' },
    attack_chain: [], iocs: [], detection_rules: [],
    threat_actor: { name: null, aliases: [], motivation: null, attribution_confidence: null, malware_families: [] },
    affected_assets: [], email_content: { subject: 's', severity_badge: 'High' },
  });

  async function newSession(): Promise<string> {
    const r = await request(app).post('/api/sessions').set(auth(adminToken)).send({ name: 'IT session', audience: 'soc', origin: 'workbench' });
    expect(r.status).toBe(200);
    return r.body.id;
  }

  describe('PUT /api/sessions/:id/result', () => {
    it('authors a result, versions it, and enforces validation/locking', async () => {
      const id = await newSession();

      // valid → version 1
      const ok = await request(app).put(`/api/sessions/${id}/result`).set(auth(adminToken)).send({ result: minimalResult() });
      expect(ok.status).toBe(200);
      expect(ok.body.version).toBe(1);

      // missing title → 400
      const bad = await request(app).put(`/api/sessions/${id}/result`).set(auth(adminToken)).send({ result: { ...minimalResult(''), } });
      expect(bad.status).toBe(400);

      // oversized attack_chain → 400
      const huge = { ...minimalResult(), attack_chain: Array.from({ length: 201 }, () => ({ technique_id: 'T1', technique_name: 'x', tactic: 'Execution', tactic_id: '', sub_technique_id: null, sub_technique_name: null, evidence: '', confidence: 'Low', detection_coverage: 'Unknown', detection_recommendation: '', order: 0 })) };
      const big = await request(app).put(`/api/sessions/${id}/result`).set(auth(adminToken)).send({ result: huge });
      expect(big.status).toBe(400);

      // stale expectedVersion → 409
      const stale = await request(app).put(`/api/sessions/${id}/result`).set(auth(adminToken)).send({ result: minimalResult('v2'), expectedVersion: 0 });
      expect(stale.status).toBe(409);

      // viewer → 403
      const viewer = await request(app).put(`/api/sessions/${id}/result`).set(auth(viewerToken)).send({ result: minimalResult() });
      expect(viewer.status).toBe(403);
    });
  });

  describe('brand-profiles governance', () => {
    it('lets a lead create/list, and resolves a session brand', async () => {
      const create = await request(app).post('/api/brand-profiles').set(auth(adminToken)).send({ name: 'Acme', isDefault: true, theme: { primary: '#ff6600' } });
      expect(create.status).toBe(201);
      const list = await request(app).get('/api/brand-profiles').set(auth(adminToken));
      expect(list.body.profiles.some((p: { name: string }) => p.name === 'Acme')).toBe(true);

      const id = await newSession();
      const resolved = await request(app).get(`/api/brand-profiles/session/${id}`).set(auth(adminToken));
      // falls back to the team default profile (Acme)
      expect(resolved.body.theme.primary).toBe('#ff6600');
    });

    it('blocks a viewer from creating a profile', async () => {
      const r = await request(app).post('/api/brand-profiles').set(auth(viewerToken)).send({ name: 'Nope' });
      expect(r.status).toBe(403);
    });
  });

  describe('delete → deleted → restore', () => {
    it('soft-deletes, lists in /deleted, and restores', async () => {
      const id = await newSession();
      expect((await request(app).delete(`/api/sessions/${id}`).set(auth(adminToken))).status).toBe(200);

      const deleted = await request(app).get('/api/sessions/deleted').set(auth(adminToken));
      expect(deleted.body.sessions.some((s: { id: string }) => s.id === id)).toBe(true);

      expect((await request(app).post(`/api/sessions/${id}/restore`).set(auth(adminToken))).status).toBe(200);
      const after = await request(app).get('/api/sessions/deleted').set(auth(adminToken));
      expect(after.body.sessions.some((s: { id: string }) => s.id === id)).toBe(false);
    });
  });

  describe('cross-session IOC correlation', () => {
    const withIoc = (title: string, value: string, actorName: string | null = null) => ({
      ...minimalResult(title),
      iocs: [{ type: 'ipv4', value, context: 'beacon', confidence: 'High' }],
      threat_actor: actorName
        ? { name: actorName, aliases: [], motivation: null, attribution_confidence: 'High', malware_families: [] }
        : { name: null, aliases: [], motivation: null, attribution_confidence: null, malware_families: [] },
    });

    it('indexes IOCs on write and correlates a shared indicator across incidents', async () => {
      const shared = '203.0.113.77';
      const a = await newSession();
      const b = await newSession();
      // b is attributed so it can surface as a suggested actor for a.
      expect((await request(app).put(`/api/sessions/${a}/result`).set(auth(adminToken)).send({ result: withIoc('A', shared) })).status).toBe(200);
      expect((await request(app).put(`/api/sessions/${b}/result`).set(auth(adminToken)).send({ result: withIoc('B', shared, 'APT-Corr') })).status).toBe(200);

      // Per-session correlations: A sees 1 other incident sharing the IP + APT-Corr suggested.
      const corr = await request(app).get(`/api/sessions/${a}/ioc-correlations`).set(auth(adminToken));
      expect(corr.status).toBe(200);
      expect(corr.body.correlations['ipv4::203.0.113.77'].others).toBe(1);
      expect(corr.body.suggestedActors.some((x: { name: string }) => x.name === 'APT-Corr')).toBe(true);

      // Occurrences: both incidents share the indicator.
      const occ = await request(app).get('/api/iocs/occurrences').query({ type: 'ipv4', value: shared }).set(auth(adminToken));
      expect(occ.status).toBe(200);
      const ids = occ.body.sessions.map((s: { id: string }) => s.id);
      expect(ids).toContain(a);
      expect(ids).toContain(b);

      // Browse list: the indicator shows a count of at least 2.
      const list = await request(app).get('/api/iocs').query({ q: shared }).set(auth(adminToken));
      expect(list.status).toBe(200);
      const hit = list.body.indicators.find((i: { value: string }) => i.value === shared);
      expect(hit?.sessionCount).toBeGreaterThanOrEqual(2);

      // Soft-delete B → it drops out of A's correlation count.
      expect((await request(app).delete(`/api/sessions/${b}`).set(auth(adminToken))).status).toBe(200);
      const corr2 = await request(app).get(`/api/sessions/${a}/ioc-correlations`).set(auth(adminToken));
      expect(corr2.body.correlations['ipv4::203.0.113.77']?.others ?? 0).toBe(0);

      // cleanup
      await request(app).post(`/api/sessions/${b}/restore`).set(auth(adminToken));
    });
  });

  describe('cases (investigations)', () => {
    const withIoc = (title: string, ip: string, actor: string | null = null) => ({
      ...minimalResult(title),
      iocs: [{ type: 'ipv4', value: ip, context: 'beacon', confidence: 'High' }],
      threat_actor: actor
        ? { name: actor, aliases: [], motivation: null, attribution_confidence: 'High', malware_families: ['Cobalt Strike'] }
        : { name: null, aliases: [], motivation: null, attribution_confidence: null, malware_families: [] },
    });

    it('creates a case, links sessions, aggregates, logs, graphs, and deletes without touching sessions', async () => {
      const s1 = await newSession();
      const s2 = await newSession();
      await request(app).put(`/api/sessions/${s1}/result`).set(auth(adminToken)).send({ result: withIoc('C-A', '198.51.100.7', 'APT-Case') });
      await request(app).put(`/api/sessions/${s2}/result`).set(auth(adminToken)).send({ result: withIoc('C-B', '198.51.100.7', 'APT-Case') });

      // create + seed with s1
      const created = await request(app).post('/api/cases').set(auth(adminToken)).send({ name: 'Op Testbed', sessionId: s1 });
      expect(created.status).toBe(200);
      const caseId = created.body.case.id as string;

      // link s2
      const link = await request(app).post(`/api/cases/${caseId}/sessions`).set(auth(adminToken)).send({ session_ids: [s2] });
      expect(link.body.added).toBe(1);

      // detail: 2 sessions, derived actor, aggregated IOC, and a 'created' + 'session_added' log
      const detail = await request(app).get(`/api/cases/${caseId}`).set(auth(adminToken));
      expect(detail.body.case.session_count).toBe(2);
      expect(detail.body.actors.some((a: { name: string }) => a.name === 'APT-Case')).toBe(true);
      expect(detail.body.aggregated_iocs.some((i: { value: string; session_count: number }) => i.value === '198.51.100.7' && i.session_count === 2)).toBe(true);
      expect(detail.body.log.length).toBeGreaterThanOrEqual(2);

      // add a note + change status → log grows, status persists
      await request(app).post(`/api/cases/${caseId}/log`).set(auth(adminToken)).send({ content: 'pivoting on the C2' });
      const patched = await request(app).patch(`/api/cases/${caseId}`).set(auth(adminToken)).send({ status: 'monitoring' });
      expect(patched.status).toBe(200);
      const detail2 = await request(app).get(`/api/cases/${caseId}`).set(auth(adminToken));
      expect(detail2.body.case.status).toBe('monitoring');
      expect(detail2.body.log.some((e: { entry_type: string }) => e.entry_type === 'status_change')).toBe(true);
      expect(detail2.body.log.some((e: { content: string }) => e.content === 'pivoting on the C2')).toBe(true);

      // graph: case + 2 sessions + actor + malware + shared ioc = 6 nodes
      const graph = await request(app).get(`/api/cases/${caseId}/graph`).set(auth(adminToken));
      expect(graph.status).toBe(200);
      const types = graph.body.nodes.map((n: { type: string }) => n.type);
      expect(types).toContain('case');
      expect(types.filter((t: string) => t === 'session')).toHaveLength(2);
      expect(types).toContain('actor');
      expect(types).toContain('ioc');
      expect(types).toContain('malware');

      // neighborhood graph seeded by the actor
      const actorId = detail2.body.actors.find((a: { name: string }) => a.name === 'APT-Case').id;
      const nbr = await request(app).get('/api/graph').query({ seed: `actor:${actorId}` }).set(auth(adminToken));
      expect(nbr.status).toBe(200);
      expect(nbr.body.nodes.filter((n: { type: string }) => n.type === 'session').length).toBe(2);

      // viewer cannot mutate
      const vp = await request(app).patch(`/api/cases/${caseId}`).set(auth(viewerToken)).send({ status: 'closed' });
      expect(vp.status).toBe(403);

      // unlink one session
      await request(app).delete(`/api/cases/${caseId}/sessions/${s2}`).set(auth(adminToken));
      const detail3 = await request(app).get(`/api/cases/${caseId}`).set(auth(adminToken));
      expect(detail3.body.case.session_count).toBe(1);

      // delete the case — sessions remain intact
      expect((await request(app).delete(`/api/cases/${caseId}`).set(auth(adminToken))).status).toBe(200);
      expect((await request(app).get(`/api/cases/${caseId}`).set(auth(adminToken))).status).toBe(404);
      expect((await request(app).get(`/api/sessions/${s1}`).set(auth(adminToken))).status).toBe(200);
    });
  });

  describe('entity annotations', () => {
    it('annotates an IOC (defang-stable key), lists, counts, gates viewer, edits/deletes', async () => {
      // IOC annotation with a fanged value…
      const create = await request(app).post('/api/annotations').set(auth(adminToken))
        .send({ entity_type: 'ioc', ioc_type: 'ipv4', ioc_value: '198.51.100.9', content: 'known sinkhole' });
      expect(create.status).toBe(200);
      const annId = create.body.annotation.id as string;

      // …is retrievable via a DEFANGED variant (server derives the same canonical key)
      const list = await request(app).get('/api/annotations').query({ entity_type: 'ioc', ioc_type: 'ipv4', ioc_value: '198[.]51[.]100[.]9' }).set(auth(adminToken));
      expect(list.status).toBe(200);
      expect(list.body.annotations).toHaveLength(1);
      expect(list.body.annotations[0].content).toBe('known sinkhole');

      // batch counts, aligned to input order
      const counts = await request(app).post('/api/annotations/counts').set(auth(adminToken)).send({
        entities: [
          { entity_type: 'ioc', ioc_type: 'ipv4', ioc_value: '198.51.100.9' },
          { entity_type: 'ioc', ioc_type: 'ipv4', ioc_value: '10.0.0.99' },
        ],
      });
      expect(counts.body.counts).toEqual([1, 0]);

      // viewer cannot annotate
      const vp = await request(app).post('/api/annotations').set(auth(viewerToken))
        .send({ entity_type: 'ioc', ioc_type: 'ipv4', ioc_value: '198.51.100.9', content: 'nope' });
      expect(vp.status).toBe(403);

      // author edits, then deletes
      expect((await request(app).patch(`/api/annotations/${annId}`).set(auth(adminToken)).send({ content: 'sinkhole (updated)' })).status).toBe(200);
      const relist = await request(app).get('/api/annotations').query({ entity_type: 'ioc', ioc_type: 'ipv4', ioc_value: '198.51.100.9' }).set(auth(adminToken));
      expect(relist.body.annotations[0].content).toBe('sinkhole (updated)');
      expect((await request(app).delete(`/api/annotations/${annId}`).set(auth(adminToken))).status).toBe(200);
      const empty = await request(app).get('/api/annotations').query({ entity_type: 'ioc', ioc_type: 'ipv4', ioc_value: '198.51.100.9' }).set(auth(adminToken));
      expect(empty.body.annotations).toHaveLength(0);
    });

    it('annotates a threat actor', async () => {
      const s = await newSession();
      await request(app).put(`/api/sessions/${s}/result`).set(auth(adminToken)).send({
        result: {
          ...minimalResult('AN actor'),
          threat_actor: { name: 'APT-Annot', aliases: [], motivation: null, attribution_confidence: 'High', malware_families: [] },
        },
      });
      const actors = await request(app).get('/api/threat-actors').query({ search: 'APT-Annot' }).set(auth(adminToken));
      const actorId = actors.body.actors.find((a: { name: string }) => a.name === 'APT-Annot').id as string;

      const create = await request(app).post('/api/annotations').set(auth(adminToken)).send({ entity_type: 'actor', actor_id: actorId, content: 'tracking infra' });
      expect(create.status).toBe(200);
      const list = await request(app).get('/api/annotations').query({ entity_type: 'actor', actor_id: actorId }).set(auth(adminToken));
      expect(list.body.annotations).toHaveLength(1);
      const counts = await request(app).post('/api/annotations/counts').set(auth(adminToken)).send({ entities: [{ entity_type: 'actor', actor_id: actorId }] });
      expect(counts.body.counts).toEqual([1]);
    });
  });

  describe('intelligence overview', () => {
    const withIoc = (title: string, ip: string, actor: string) => ({
      ...minimalResult(title),
      iocs: [{ type: 'ipv4', value: ip, context: 'beacon', confidence: 'High' }],
      attack_chain: [{ technique_id: 'T1566', technique_name: 'Phishing', tactic: 'Initial Access', tactic_id: 'TA0001', sub_technique_id: null, sub_technique_name: null, evidence: 'e', confidence: 'High', detection_coverage: 'Unknown', detection_recommendation: '', order: 0 }],
      threat_actor: { name: actor, aliases: [], motivation: null, attribution_confidence: 'High', malware_families: [] },
    });

    it('surfaces holdings — counts, top IOCs/actors/techniques — team-scoped', async () => {
      const sharedIp = '192.0.2.140';
      const a = await newSession();
      const b = await newSession();
      expect((await request(app).put(`/api/sessions/${a}/result`).set(auth(adminToken)).send({ result: withIoc('Intel-A', sharedIp, 'APT-Intel') })).status).toBe(200);
      expect((await request(app).put(`/api/sessions/${b}/result`).set(auth(adminToken)).send({ result: withIoc('Intel-B', sharedIp, 'APT-Intel') })).status).toBe(200);

      const ov = await request(app).get('/api/intel/overview').set(auth(adminToken));
      expect(ov.status).toBe(200);
      expect(ov.body.counts.indicators).toBeGreaterThanOrEqual(1);
      expect(ov.body.counts.actors).toBeGreaterThanOrEqual(1);
      expect(ov.body.counts.techniques).toBeGreaterThanOrEqual(1);

      // the shared IOC surfaces in top_iocs with a count of at least 2
      const topIoc = ov.body.top_iocs.find((i: { value: string }) => i.value === sharedIp);
      expect(topIoc?.sessionCount).toBeGreaterThanOrEqual(2);
      // the attributed actor surfaces in top_actors
      expect(ov.body.top_actors.some((x: { name: string }) => x.name === 'APT-Intel')).toBe(true);
      // the technique surfaces in top_techniques
      expect(ov.body.top_techniques.some((t: { technique_id: string }) => t.technique_id === 'T1566')).toBe(true);
      // recent activity is present
      expect(ov.body.recent_sessions.length).toBeGreaterThanOrEqual(1);

      // team scoping: a different team sees none of this team's holdings
      const otherTeam = { Authorization: `Bearer ${adminToken}`, 'X-Team-Id': 'nonexistent_team' };
      const ovOther = await request(app).get('/api/intel/overview').set(otherTeam);
      expect(ovOther.status).toBe(200);
      expect(ovOther.body.top_iocs.some((i: { value: string }) => i.value === sharedIp)).toBe(false);
    });

    it('orders /api/iocs by last_seen with order=recent', async () => {
      const older = '192.0.2.201';
      const newer = '192.0.2.202';
      const s1 = await newSession();
      await request(app).put(`/api/sessions/${s1}/result`).set(auth(adminToken)).send({ result: { ...minimalResult('Ord-1'), iocs: [{ type: 'ipv4', value: older, context: 'c', confidence: 'High' }] } });
      // small delay so last_seen differs
      await new Promise((r) => setTimeout(r, 5));
      const s2 = await newSession();
      await request(app).put(`/api/sessions/${s2}/result`).set(auth(adminToken)).send({ result: { ...minimalResult('Ord-2'), iocs: [{ type: 'ipv4', value: newer, context: 'c', confidence: 'High' }] } });

      const recent = await request(app).get('/api/iocs').query({ order: 'recent', limit: 50 }).set(auth(adminToken));
      expect(recent.status).toBe(200);
      const idxNewer = recent.body.indicators.findIndex((i: { value: string }) => i.value === newer);
      const idxOlder = recent.body.indicators.findIndex((i: { value: string }) => i.value === older);
      expect(idxNewer).toBeGreaterThanOrEqual(0);
      expect(idxOlder).toBeGreaterThanOrEqual(0);
      expect(idxNewer).toBeLessThan(idxOlder);
    });

    it('paginates + sorts holdings per kind via /api/intel/holdings', async () => {
      // each kind returns a shaped page and honours limit + hasMore
      const ind = await request(app).get('/api/intel/holdings').query({ kind: 'indicators', order: 'mentions', limit: 2 }).set(auth(adminToken));
      expect(ind.status).toBe(200);
      expect(Array.isArray(ind.body.items)).toBe(true);
      expect(ind.body.items.length).toBeLessThanOrEqual(2);
      expect(typeof ind.body.hasMore).toBe('boolean');
      if (ind.body.items[0]) expect(ind.body.items[0]).toHaveProperty('sessionCount');

      const act = await request(app).get('/api/intel/holdings').query({ kind: 'actors', order: 'mentions', limit: 5 }).set(auth(adminToken));
      expect(act.status).toBe(200);
      if (act.body.items[0]) expect(act.body.items[0]).toHaveProperty('session_count');

      const tec = await request(app).get('/api/intel/holdings').query({ kind: 'techniques', order: 'recent', limit: 5 }).set(auth(adminToken));
      expect(tec.status).toBe(200);
      if (tec.body.items[0]) expect(tec.body.items[0]).toHaveProperty('technique_id');

      const ses = await request(app).get('/api/intel/holdings').query({ kind: 'sessions', order: 'severity', limit: 5 }).set(auth(adminToken));
      expect(ses.status).toBe(200);
      if (ses.body.items[0]) expect(ses.body.items[0]).toHaveProperty('created_at');

      // offset paginates: page 2 of size 1 differs from page 1 when >1 indicator exists
      const p1 = await request(app).get('/api/intel/holdings').query({ kind: 'indicators', order: 'mentions', limit: 1, offset: 0 }).set(auth(adminToken));
      const p2 = await request(app).get('/api/intel/holdings').query({ kind: 'indicators', order: 'mentions', limit: 1, offset: 1 }).set(auth(adminToken));
      if (p1.body.items[0] && p2.body.items[0]) {
        expect(`${p1.body.items[0].type}:${p1.body.items[0].norm}`).not.toBe(`${p2.body.items[0].type}:${p2.body.items[0].norm}`);
      }

      // unknown kind → 400
      const bad = await request(app).get('/api/intel/holdings').query({ kind: 'nope' }).set(auth(adminToken));
      expect(bad.status).toBe(400);
    });
  });
});
