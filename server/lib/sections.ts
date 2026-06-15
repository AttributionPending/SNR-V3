/**
 * Brief Sections — configurable schema for the Phase 2 narrative output.
 *
 * Each BriefSection maps 1-to-1 with:
 *   • A field in the EMAIL_TOOL_SCHEMA sent to Claude (for text/bullets/numbered types)
 *   • A rendered block in the HTML email and plain-text body
 *
 * "Auto" section types (techniques / iocs) are rendered from Phase 1 data
 * and do NOT add a field to the Phase 2 schema — Claude doesn't generate them.
 */

export type SectionType = 'text' | 'bullets' | 'numbered' | 'techniques' | 'iocs';

export interface BriefSection {
  key: string;        // JSON field key / HTML block identifier
  label: string;      // Human-readable section heading shown in the email
  description: string; // Schema description sent to Claude (tells it what to write)
  type: SectionType;
  enabled: boolean;
}

/** Section types whose content is auto-rendered from Phase 1 results */
export const AUTO_TYPES = new Set<SectionType>(['techniques', 'iocs']);

/**
 * Default sections — intelligence brief format.
 * Used when no custom sections are saved in settings.
 */
export const DEFAULT_SECTIONS: BriefSection[] = [
  {
    key: 'threat_action',
    label: 'Threat Action',
    type: 'text',
    description: 'Brief 1-2 sentence summary of the threat report — what the adversary did and why it matters',
    enabled: true,
  },
  {
    key: 'attack_overview',
    label: 'Attack Overview',
    type: 'text',
    description: '1-3 paragraphs providing an overview of the attack or report — context, timeline, and key events',
    enabled: true,
  },
  {
    key: 'technical_analysis',
    label: 'Technical Analysis',
    type: 'text',
    description: '1-3 paragraphs explaining how the adversary conducted the attack — TTPs, tools, and tradecraft',
    enabled: true,
  },
  {
    key: 'impact_assessment',
    label: 'Impact Assessment',
    type: 'text',
    description: '1-3 paragraphs assessing impact drawn from organizational context — affected systems, data, and operations',
    enabled: true,
  },
  {
    key: 'threat_actor_info',
    label: 'Threat Actor / Malware Family',
    type: 'text',
    description: 'Known threat actor name, associated malware family, aliases, and attribution confidence level',
    enabled: true,
  },
  {
    key: 'techniques',
    label: 'MITRE ATT&CK Mapping',
    type: 'techniques',
    description: 'Auto-populated from Phase 1 analysis — technique IDs with brief statements on how they were applied',
    enabled: true,
  },
  {
    key: 'behavioral_indicators',
    label: 'Behavioral Indicators',
    type: 'text',
    description: '1-3 paragraphs explaining the behavioral indicators observed — patterns, anomalies, and TTPs',
    enabled: true,
  },
  {
    key: 'iocs',
    label: 'Indicators of Compromise',
    type: 'iocs',
    description: 'Auto-populated from Phase 1 technical analysis — top 15 most actionable',
    enabled: false,
  },
  {
    key: 'references',
    label: 'References',
    type: 'text',
    description: 'Source references — report names, URLs, threat intel feeds, and relevant CVEs cited in the analysis',
    enabled: true,
  },
  {
    key: 'distribution_info',
    label: 'Distribution Information',
    type: 'text',
    description: 'Distribution handling instructions — TLP guidance, authorized recipients, and need-to-know restrictions',
    enabled: true,
  },
];

/**
 * Parse sections from a JSON string (as stored in settings).
 * Falls back to DEFAULT_SECTIONS on invalid/empty input.
 */
export function parseSections(json: string): BriefSection[] {
  if (!json?.trim()) return DEFAULT_SECTIONS;
  try {
    const parsed = JSON.parse(json);
    if (Array.isArray(parsed) && parsed.length > 0) return parsed as BriefSection[];
  } catch { /* fall through */ }
  return DEFAULT_SECTIONS;
}

/**
 * Build the EMAIL_TOOL_SCHEMA dynamically from the sections config.
 * Only text/bullets/numbered sections generate schema fields.
 * Auto sections (techniques/iocs) are rendered from Phase 1 — no schema field.
 */
export function buildEmailSchema(sections: BriefSection[]): {
  type: 'object';
  properties: Record<string, unknown>;
  required: string[];
} {
  const properties: Record<string, unknown> = {
    subject: {
      type: 'string',
      description: 'TLP:{LEVEL} | {Severity} | {ThreatCategory} | {YYYY-MM-DD}',
    },
    severity_badge: {
      type: 'string',
      enum: ['Critical', 'High', 'Medium', 'Low', 'Informational'],
    },
  };
  const required = ['subject', 'severity_badge'];

  for (const section of sections) {
    if (!section.enabled) continue;
    if (AUTO_TYPES.has(section.type)) continue;
    properties[section.key] = {
      type: 'string',
      description: section.description,
    };
    required.push(section.key);
  }

  return { type: 'object', properties, required };
}

/**
 * Build human-readable section guidance injected into the Phase 2 prompt.
 * Tells Claude which fields to populate and what each should contain.
 */
export function buildSectionGuidance(sections: BriefSection[]): string {
  const textSections = sections.filter(s => s.enabled && !AUTO_TYPES.has(s.type));
  const autoSections  = sections.filter(s => s.enabled &&  AUTO_TYPES.has(s.type));
  const lines: string[] = [];

  if (textSections.length > 0) {
    lines.push('Required output fields — populate each one:');
    for (const s of textSections) {
      lines.push(`  • ${s.key}: ${s.description}`);
    }
  }

  if (autoSections.length > 0) {
    lines.push('');
    lines.push('Auto-rendered sections (populated from Phase 1 data, no separate field needed):');
    for (const s of autoSections) {
      lines.push(`  • ${s.label}`);
    }
  }

  return lines.join('\n');
}
