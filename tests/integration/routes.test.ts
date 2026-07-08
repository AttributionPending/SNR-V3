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
});
