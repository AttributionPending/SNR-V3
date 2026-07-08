import { describe, it, expect } from 'vitest';
import { buildEml, buildHtmlBody } from '../server/lib/eml.js';
import type { AnalysisResult } from '../server/lib/claude.js';

function result(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    incident_summary: { title: 'Incident', severity: 'High', confidence: 'High', description: 'd', analyst_notes: '' },
    attack_chain: [{ technique_id: 'T1059.001', technique_name: '<script>alert(1)</script>', tactic: 'Execution', tactic_id: '', sub_technique_id: null, sub_technique_name: null, evidence: 'ev', confidence: 'High', detection_coverage: 'Unknown', detection_recommendation: '', order: 0 }],
    iocs: [{ type: 'domain', value: '"><img src=x onerror=alert(1)>', context: 'c', confidence: 'High' }],
    detection_rules: [],
    threat_actor: { name: null, aliases: [], motivation: null, attribution_confidence: null, malware_families: [] },
    affected_assets: [],
    email_content: { subject: 'fallback subject', severity_badge: 'High' },
    ...overrides,
  } as AnalysisResult;
}
const base = { audience: 'soc', tlp: 'AMBER' as never, analystEmail: 'a@org.com', analystName: 'CTI Analyst' };

describe('buildHtmlBody — escaping (security)', () => {
  it('escapes authored technique names in the rendered HTML (no raw script injection)', () => {
    const html = buildHtmlBody({
      email: result().email_content, audienceLabel: 'SOC', tlp: 'AMBER',
      tlpColor: '#d97706', tlpTextColor: '#ffffff', severityColor: '#374151', severityBg: '#f9fafb',
      result: result(),
    });
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;'); // escaped form is present in the technique table
  });
});

describe('buildEml — sender identity headers', () => {
  it('applies From / Reply-To / CC / BCC and a token-substituted subject', () => {
    const eml = buildEml({
      ...base,
      result: result(),
      sender: {
        fromName: 'Acme SOC', fromEmail: 'soc@acme.example', replyTo: 'reply@acme.example',
        cc: 'cc1@acme.example', bcc: 'bcc1@acme.example', preheader: 'preview',
        subjectTemplate: 'BRIEF {tlp} {severity}',
      },
    });
    expect(eml).toMatch(/From: Acme SOC <soc@acme\.example>/);
    expect(eml).toMatch(/Reply-To: reply@acme\.example/);
    expect(eml).toMatch(/Cc: .*cc1@acme\.example/i);
    expect(eml).toMatch(/Bcc: .*bcc1@acme\.example/i);
    expect(eml).toMatch(/Subject: .*BRIEF AMBER High/);
  });

  it('falls back to the analyst identity and email subject when no sender is set', () => {
    const eml = buildEml({ ...base, result: result() });
    expect(eml).toMatch(/From: CTI Analyst <a@org\.com>/);
    expect(eml).toContain('fallback subject');
  });
});
