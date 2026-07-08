import { describe, it, expect } from 'vitest';
import { buildMarkdownReport } from '../server/lib/report.js';
import { DEFAULT_SECTIONS } from '../server/lib/sections.js';
import type { AnalysisResult } from '../server/lib/claude.js';

function result(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    incident_summary: { title: 'TinyRCT Backdoor', severity: 'High', confidence: 'High', description: 'A .NET loader.', analyst_notes: '' },
    attack_chain: [{ technique_id: 'T1059.001', technique_name: 'PowerShell', tactic: 'Execution', tactic_id: '', sub_technique_id: null, sub_technique_name: null, evidence: 'encoded PS', confidence: 'High', detection_coverage: 'Detection Gap', detection_recommendation: '', order: 0 }],
    iocs: [{ type: 'domain', value: 'evil.example', context: 'C2', confidence: 'High' }],
    detection_rules: [],
    threat_actor: { name: null, aliases: [], motivation: null, attribution_confidence: null, malware_families: [] },
    affected_assets: [],
    email_content: { subject: 's', severity_badge: 'High' },
    ...overrides,
  } as AnalysisResult;
}
const opts = { analystName: 'CTI Analyst', orgName: 'ACME', tlp: 'AMBER', audience: 'soc' };

describe('buildMarkdownReport', () => {
  it('renders the incident title, technique, and IOC in the structured report', () => {
    const md = buildMarkdownReport(result(), DEFAULT_SECTIONS, opts);
    expect(md).toContain('TinyRCT Backdoor');
    expect(md).toContain('T1059.001');
    expect(md).toContain('PowerShell');
  });

  it('adds the original-research provenance line only for workbench origin', () => {
    const authored = buildMarkdownReport(result(), DEFAULT_SECTIONS, { ...opts, origin: 'workbench' });
    const analyzed = buildMarkdownReport(result(), DEFAULT_SECTIONS, { ...opts, origin: 'analysis' });
    expect(authored).toContain('Original research — analyst-authored');
    expect(analyzed).not.toContain('Original research');
  });
});
