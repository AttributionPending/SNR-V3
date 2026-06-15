import type { BriefSection } from '@/types';

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

export const AUTO_TYPES = new Set<BriefSection['type']>(['techniques', 'iocs']);

export function parseSections(json: string): BriefSection[] {
  if (!json?.trim()) return DEFAULT_SECTIONS;
  try {
    const parsed = JSON.parse(json);
    if (Array.isArray(parsed) && parsed.length > 0) return parsed as BriefSection[];
  } catch { /* fall through */ }
  return DEFAULT_SECTIONS;
}
