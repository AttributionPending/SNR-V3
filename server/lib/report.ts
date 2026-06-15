import type { AnalysisResult } from './claude.js';
import { type BriefSection, DEFAULT_SECTIONS, AUTO_TYPES } from './sections.js';
import { defang } from './defang.js';

/**
 * Build a Markdown CTI report.
 *
 * When `opts.template` is set (a saved Report Template), the report is rendered
 * by substituting {field} and {{BLOCK}} tokens in that template. When it is
 * empty, the original structured generator runs — byte-for-byte unchanged — so
 * existing exports are unaffected.
 *
 * Both paths read the same Phase-1 data and the same `sections` config used by
 * the HTML email and plain-text renderers.
 */
export function buildMarkdownReport(
  result: AnalysisResult,
  sections: BriefSection[],
  opts: {
    analystName: string;
    orgName: string;
    tlp: string;
    audience: string;
    /** Saved Report Template (token-based). Empty = built-in structured layout. */
    template?: string;
  },
): string {
  const email = result.email_content;
  const date  = new Date().toISOString().split('T')[0];
  const year  = new Date().getFullYear();

  const hashBase = (result.incident_summary.title + date).replace(/\W/g, '').slice(0, 8).toUpperCase();
  const reportId = `CTI-${year}-${hashBase || '001'}`;

  const severity  = (email.severity_badge as string) || result.incident_summary.severity;
  const analystLine = opts.analystName + (opts.orgName ? ` — ${opts.orgName}` : '');
  const confidence =
    result.threat_actor?.attribution_confidence ??
    (['Critical', 'High'].includes(result.incident_summary.severity) ? 'High' :
      result.incident_summary.severity === 'Medium' ? 'Medium' : 'Low');

  // ── Shared block renderers (used by both the template path and reused logic) ─
  const techniqueTable = (): string => {
    if (result.attack_chain.length === 0) return '*No ATT&CK techniques mapped.*';
    return [
      '| Technique ID | Tactic | Technique Name | Confidence |',
      '|---|---|---|---|',
      ...result.attack_chain.map(t => `| ${t.technique_id} | ${t.tactic} | ${t.technique_name} | ${t.confidence} |`),
    ].join('\n');
  };

  const techniqueDetail = (): string => {
    if (result.attack_chain.length === 0) return '*No ATT&CK techniques mapped.*';
    const byTactic = new Map<string, typeof result.attack_chain>();
    for (const t of result.attack_chain) {
      if (!byTactic.has(t.tactic)) byTactic.set(t.tactic, []);
      byTactic.get(t.tactic)!.push(t);
    }
    const out: string[] = [];
    for (const [tactic, techs] of byTactic) {
      out.push(`### ${tactic}`, '');
      for (const t of techs) {
        out.push(`**${t.technique_id} — ${t.technique_name}** *(${t.confidence} confidence)*`, `> ${t.evidence}`, '');
      }
    }
    return out.join('\n').trim();
  };

  const iocTable = (types?: string[]): string => {
    const iocs = types ? result.iocs.filter(i => types.includes(i.type)) : result.iocs;
    if (iocs.length === 0) return '*No indicators of compromise extracted.*';
    return [
      '| Type | Value | Context | Confidence |',
      '|---|---|---|---|',
      ...iocs.map(i => `| \`${i.type.toUpperCase()}\` | \`${defang(i.value, i.type)}\` | ${i.context} | ${i.confidence} |`),
    ].join('\n');
  };

  const affectedAssetsTable = (): string => {
    if (result.affected_assets.length === 0) return '*No affected assets identified.*';
    return [
      '| Hostname | IP | Role | Confidence |',
      '|---|---|---|---|',
      ...result.affected_assets.map(a => `| ${a.hostname || '—'} | ${a.ip || '—'} | ${a.role || '—'} | ${a.compromise_confidence || '—'} |`),
    ].join('\n');
  };

  const threatActorBlock = (): string => {
    const ta = result.threat_actor;
    if (!ta?.name) return '*No threat actor attributed.*';
    const out = [`**Name:** ${ta.name}`];
    if (ta.aliases?.length) out.push(`**Aliases:** ${ta.aliases.join(', ')}`);
    if (ta.motivation) out.push(`**Motivation:** ${ta.motivation}`);
    if (ta.attribution_confidence) out.push(`**Attribution Confidence:** ${ta.attribution_confidence}`);
    if (ta.intrusion_set) out.push(`**Intrusion Set:** ${ta.intrusion_set}`);
    if (ta.campaign_name) out.push(`**Campaign:** ${ta.campaign_name}`);
    if (ta.malware_families?.length) out.push(`**Malware Families:** ${ta.malware_families.join(', ')}`);
    const info = email.threat_actor_info as string | undefined;
    if (info) out.push('', info);
    return out.join('\n');
  };

  const campaignTimeline = (): string => {
    if (result.attack_chain.length === 0) return '*No campaign timeline available.*';
    return result.attack_chain
      .slice()
      .sort((a, b) => (a.order || 0) - (b.order || 0))
      .map((t, i) => `${i + 1}. **${t.tactic}** — ${t.technique_name} (${t.technique_id})`)
      .join('\n');
  };

  // Render a single configurable section (## heading + content/table)
  const renderSection = (s: BriefSection): string => {
    if (s.type === 'techniques') return `## ${s.label}\n\n${techniqueTable()}`;
    if (s.type === 'iocs') return `## ${s.label}\n\n${iocTable()}`;
    const content = (email[s.key] as string) ?? '';
    return content ? `## ${s.label}\n\n${content}` : '';
  };

  // {{SECTIONS}} renders the narrative sections only; techniques/IOC tables are
  // placed explicitly via {{ATTACK_TABLE}} / {{IOC_TABLE}} to avoid duplication.
  const renderAllSections = (): string =>
    sections.filter(s => s.enabled && !AUTO_TYPES.has(s.type)).map(renderSection).filter(Boolean).join('\n\n---\n\n');

  // ── Template path: substitute tokens, then return ─────────────────────────
  if (opts.template && opts.template.trim()) {
    const fieldValues: Record<string, string> = {
      date,
      tlp: opts.tlp,
      report_id: reportId,
      analyst_name: opts.analystName,
      org_name: opts.orgName,
      confidence,
      severity,
      summary: (email.threat_action as string) || (email.summary as string) || result.incident_summary.description || '',
      affected_assets: result.affected_assets.map(a => a.hostname || a.ip || 'unknown').join(', ') || 'None identified',
      ioc_count: String(result.iocs.length),
      technique_count: String(result.attack_chain.length),
      threat_actor_name: result.threat_actor?.name || 'Unattributed',
      threat_actor_aliases: (result.threat_actor?.aliases || []).join(', '),
      threat_actor_motivation: result.threat_actor?.motivation || 'Unknown',
      threat_actor_confidence: result.threat_actor?.attribution_confidence || 'Unknown',
      initial_access: result.attack_chain.slice().sort((a, b) => (a.order || 0) - (b.order || 0))[0]?.technique_name || 'Unknown',
      motivation: result.threat_actor?.motivation || 'Unknown',
    };

    const blockRenderers: Record<string, () => string> = {
      SECTIONS: renderAllSections,
      ATTACK_TABLE: techniqueTable,
      ATTACK_CHAIN: techniqueDetail,
      IOC_TABLE: () => iocTable(),
      EMAIL_IOCS: () => iocTable(['email', 'domain', 'url']),
      AFFECTED_ASSETS_TABLE: affectedAssetsTable,
      THREAT_ACTOR: threatActorBlock,
      CAMPAIGN_TIMELINE: campaignTimeline,
      // Legacy section tokens — map to current keys with fallbacks
      OBSERVATIONS: () => (email.behavioral_indicators as string) || (email.observations as string) || '*No behavioral indicators noted.*',
      ACTIONS: () => (email.recommended_actions as string) || '*No recommended actions specified.*',
      NEXT_STEPS: () => (email.next_steps as string) || (email.distribution_info as string) || '*No next steps specified.*',
    };

    let out = opts.template;
    // Block tokens first: {{SECTION:key}} then {{TOKEN}}
    out = out.replace(/\{\{SECTION:([a-z0-9_]+)\}\}/g, (_m, key: string) => {
      const sec = sections.find(s => s.key === key && s.enabled);
      return sec ? renderSection(sec) : '';
    });
    out = out.replace(/\{\{([A-Z_]+)\}\}/g, (m, tok: string) => (tok in blockRenderers ? blockRenderers[tok]() : m));
    // Field tokens
    out = out.replace(/\{([a-z_]+)\}/g, (m, tok: string) => (tok in fieldValues ? fieldValues[tok] : m));
    return out;
  }

  // ── Default structured path (unchanged) ───────────────────────────────────
  const lines: string[] = [
    `# ${severity}`,
    '',
    `**Report Title:** ${result.incident_summary.title}`,
    `**Date:** ${date}`,
    `**Severity:** ${severity}`,
    `**Classification:** TLP:${opts.tlp}`,
    `**Report ID:** ${reportId}`,
    `**Author/Team:** ${analystLine}`,
    `**Confidence Level:** ${confidence}`,
    '',
    '---',
    '',
  ];

  for (const section of sections.filter(s => s.enabled)) {
    if (section.type === 'techniques') {
      lines.push(`## ${section.label}`, '');

      if (result.attack_chain.length > 0) {
        lines.push(
          '| Technique ID | Tactic | Technique Name | Confidence |',
          '|---|---|---|---|',
          ...result.attack_chain.map(t =>
            `| ${t.technique_id} | ${t.tactic} | ${t.technique_name} | ${t.confidence} |`
          ),
        );
        lines.push('');

        const byTactic = new Map<string, typeof result.attack_chain>();
        for (const t of result.attack_chain) {
          if (!byTactic.has(t.tactic)) byTactic.set(t.tactic, []);
          byTactic.get(t.tactic)!.push(t);
        }
        for (const [tactic, techs] of byTactic) {
          lines.push(`### ${tactic}`, '');
          for (const t of techs) {
            lines.push(
              `**${t.technique_id} — ${t.technique_name}** *(${t.confidence} confidence)*`,
              `> ${t.evidence}`,
              '',
            );
          }
        }
      } else {
        lines.push('*No ATT&CK techniques mapped.*', '');
      }

      lines.push('---', '');

    } else if (section.type === 'iocs') {
      lines.push(`## ${section.label}`, '');

      if (result.iocs.length > 0) {
        lines.push(
          '| Type | Value | Context | Confidence |',
          '|---|---|---|---|',
          ...result.iocs.map(i =>
            `| \`${i.type.toUpperCase()}\` | \`${defang(i.value, i.type)}\` | ${i.context} | ${i.confidence} |`
          ),
        );
      } else {
        lines.push('*No indicators of compromise extracted.*');
      }
      lines.push('', '---', '');

    } else {
      const content = (email[section.key] as string) ?? '';
      if (content) {
        lines.push(`## ${section.label}`, '', content, '', '---', '');
      }
    }
  }

  lines.push(`*Generated by SNR — Signal to Noise | TLP:${opts.tlp} | ${date}*`);

  return lines.join('\n');
}
